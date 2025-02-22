use crate::events::EngineEvent;
use tracing;

#[derive(Debug, Clone)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

pub trait Logger: Send {
    fn log(&self, log_level: LogLevel, event: EngineEvent);
    fn clone_dyn(&self) -> Box<dyn Logger>;
}

impl Clone for Box<dyn Logger> {
    fn clone(&self) -> Self {
        self.clone_dyn()
    }
}

#[derive(Clone)]
pub struct StdIoLogger {}

impl StdIoLogger {
    pub fn new() -> StdIoLogger {
        // TODO(benjaminch): configure tracing library in here, should be transparent for parent caller.
        StdIoLogger {}
    }
}

impl Default for StdIoLogger {
    fn default() -> Self {
        StdIoLogger::new()
    }
}

impl Logger for StdIoLogger {
    fn log(&self, log_level: LogLevel, event: EngineEvent) {
        let event_details = event.get_details();
        let stage = event_details.stage();

        tracing::span!(
            tracing::Level::INFO,
            "std_io_logger",
            organization_id = event_details.organisation_id().short(),
            cluster_id = event_details.cluster_id().short(),
            execution_id = event_details.execution_id().short(),
            provider = event_details.provider_kind().to_string().as_str(),
            stage = stage.to_string().as_str(),
            step = stage.sub_step_name().as_str(),
            transmitter = event_details.transmitter().to_string().as_str(),
        )
        .in_scope(|| {
            match log_level {
                LogLevel::Debug => debug!("{}", event.get_message()),
                LogLevel::Info => info!("{}", event.get_message()),
                LogLevel::Warning => warn!("{}", event.get_message()),
                LogLevel::Error => error!("{}", event.get_message()),
            };
        });
    }

    fn clone_dyn(&self) -> Box<dyn Logger> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_provider::scaleway::application::Region;
    use crate::cloud_provider::Kind;
    use crate::errors::EngineError;
    use crate::events::{EnvironmentStep, EventDetails, EventMessage, InfrastructureStep, Stage, Transmitter};
    use crate::models::QoveryIdentifier;
    use tracing_test::traced_test;
    use url::Url;
    use uuid::Uuid;

    struct TestCase<'a> {
        log_level: LogLevel,
        event: EngineEvent,
        description: &'a str,
    }

    #[traced_test]
    #[test]
    fn test_log() {
        // setup:
        let orga_id = QoveryIdentifier::new(Uuid::new_v4().to_string());
        let cluster_id = QoveryIdentifier::new(Uuid::new_v4().to_string());
        let cluster_name = format!("qovery-{}", cluster_id);
        let execution_id = QoveryIdentifier::new(Uuid::new_v4().to_string());
        let app_id = QoveryIdentifier::new(Uuid::new_v4().to_string());
        let app_name = format!("simple-app-{}", app_id);
        let qovery_message = "Qovery message";
        let user_message = "User message";
        let raw_message = "Raw message";
        let raw_message_safe = "Raw message safe";
        let link = Url::parse("https://qovery.com").expect("cannot parse Url");
        let hint = "An hint !";

        let test_cases = vec![
            TestCase {
                log_level: LogLevel::Error,
                event: EngineEvent::Error(EngineError::new_unknown(
                    EventDetails::new(
                        Kind::Scw,
                        orga_id.clone(),
                        cluster_id.clone(),
                        execution_id.clone(),
                        Region::Paris.as_str().to_string(),
                        Stage::Infrastructure(InfrastructureStep::Create),
                        Transmitter::Kubernetes(cluster_id.to_string(), cluster_name.to_string()),
                    ),
                    qovery_message.to_string(),
                    user_message.to_string(),
                    Some(raw_message.to_string()),
                    Some(raw_message_safe.to_string()),
                    Some(link.clone()),
                    Some(hint.to_string()),
                )),
                description: "Error event",
            },
            TestCase {
                log_level: LogLevel::Info,
                event: EngineEvent::Deploying(
                    EventDetails::new(
                        Kind::Scw,
                        orga_id.clone(),
                        cluster_id.clone(),
                        execution_id.clone(),
                        Region::Paris.as_str().to_string(),
                        Stage::Infrastructure(InfrastructureStep::Create),
                        Transmitter::Kubernetes(cluster_id.to_string(), cluster_name.to_string()),
                    ),
                    EventMessage::new(raw_message.to_string(), Some(raw_message_safe.to_string())),
                ),
                description: "Deploying info event",
            },
            TestCase {
                log_level: LogLevel::Debug,
                event: EngineEvent::Pausing(
                    EventDetails::new(
                        Kind::Scw,
                        orga_id.clone(),
                        cluster_id.clone(),
                        execution_id.clone(),
                        Region::Paris.as_str().to_string(),
                        Stage::Environment(EnvironmentStep::Pause),
                        Transmitter::Application(app_id.to_string(), app_name.to_string()),
                    ),
                    EventMessage::new(raw_message.to_string(), Some(raw_message_safe.to_string())),
                ),
                description: "Pausing application debug event",
            },
            TestCase {
                log_level: LogLevel::Warning,
                event: EngineEvent::Pausing(
                    EventDetails::new(
                        Kind::Scw,
                        orga_id.clone(),
                        cluster_id.clone(),
                        execution_id.clone(),
                        Region::Paris.as_str().to_string(),
                        Stage::Environment(EnvironmentStep::Delete),
                        Transmitter::Application(app_id.to_string(), app_name.to_string()),
                    ),
                    EventMessage::new(raw_message.to_string(), Some(raw_message_safe.to_string())),
                ),
                description: "Deleting application warning event",
            },
        ];

        let logger = StdIoLogger::new();

        for tc in test_cases {
            // execute:
            logger.log(tc.log_level.clone(), tc.event.clone());

            // validate:
            assert!(
                logs_contain(match tc.log_level {
                    LogLevel::Debug => "DEBUG",
                    LogLevel::Info => "INFO",
                    LogLevel::Warning => "WARN",
                    LogLevel::Error => "ERROR",
                }),
                "{}",
                tc.description
            );

            assert!(
                logs_contain(format!("organization_id=\"{}\"", orga_id.short()).as_str()),
                "{}",
                tc.description
            );
            assert!(
                logs_contain(format!("cluster_id=\"{}\"", cluster_id.short()).as_str()),
                "{}",
                tc.description
            );
            assert!(
                logs_contain(format!("execution_id=\"{}\"", execution_id.short()).as_str()),
                "{}",
                tc.description
            );

            let details = tc.event.get_details();
            assert!(
                logs_contain(format!("provider=\"{}\"", details.provider_kind().to_string()).as_str()),
                "{}",
                tc.description
            );

            assert!(
                logs_contain(format!("stage=\"{}\"", details.stage().to_string()).as_str()),
                "{}",
                tc.description
            );
            assert!(
                logs_contain(format!("step=\"{}\"", details.stage().sub_step_name().to_string()).as_str()),
                "{}",
                tc.description
            );
            assert!(
                logs_contain(format!("transmitter=\"{}\"", details.transmitter().to_string()).as_str()),
                "{}",
                tc.description
            );

            let message = tc.event.get_message().to_string();
            assert!(logs_contain(&message), "{}", tc.description);
        }
    }
}
