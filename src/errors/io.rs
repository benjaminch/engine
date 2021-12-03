use super::url::Url;
use crate::cloud_provider::Kind;
use crate::errors;
use crate::models::QoveryIdentifier;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub enum Severity {
    Warning,
    Critical,
}

impl From<Severity> for errors::Severity {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Warning => errors::Severity::Warning,
            Severity::Critical => errors::Severity::Critical,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum Stage {
    Infrastructure(InfrastructureStep),
    Environment(EnvironmentStep),
}

impl From<Stage> for errors::Stage {
    fn from(stage: Stage) -> Self {
        match stage {
            Stage::Infrastructure(steps) => errors::Stage::Infrastructure(errors::InfrastructureStep::from(steps)),
            Stage::Environment(steps) => errors::Stage::Environment(errors::EnvironmentStep::from(steps)),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum InfrastructureStep {
    Instantiate,
    Create,
    Pause,
    Upgrade,
    Delete,
}

impl From<InfrastructureStep> for errors::InfrastructureStep {
    fn from(step: InfrastructureStep) -> Self {
        match step {
            InfrastructureStep::Instantiate => errors::InfrastructureStep::Instantiate,
            InfrastructureStep::Create => errors::InfrastructureStep::Create,
            InfrastructureStep::Upgrade => errors::InfrastructureStep::Upgrade,
            InfrastructureStep::Delete => errors::InfrastructureStep::Delete,
            InfrastructureStep::Pause => errors::InfrastructureStep::Pause,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum EnvironmentStep {
    Build,
    Deploy,
    Update,
    Delete,
}

impl From<EnvironmentStep> for errors::EnvironmentStep {
    fn from(step: EnvironmentStep) -> Self {
        match step {
            EnvironmentStep::Build => errors::EnvironmentStep::Build,
            EnvironmentStep::Deploy => errors::EnvironmentStep::Deploy,
            EnvironmentStep::Update => errors::EnvironmentStep::Update,
            EnvironmentStep::Delete => errors::EnvironmentStep::Delete,
        }
    }
}

type TransmitterId = String;
type TransmitterName = String;
type TransmitterType = String;

#[derive(Serialize, Deserialize)]
pub enum Transmitter {
    Engine,
    BuildPlatform(TransmitterId, TransmitterName),
    ContainerRegistry(TransmitterId, TransmitterName),
    CloudProvider(TransmitterId, TransmitterName),
    Kubernetes(TransmitterId, TransmitterName),
    DnsProvider(TransmitterId, TransmitterName),
    ObjectStorage(TransmitterId, TransmitterName),
    Environment(TransmitterId, TransmitterName),
    Database(TransmitterId, TransmitterType, TransmitterName),
    Application(TransmitterId, TransmitterName),
    Router(TransmitterId, TransmitterName),
}

impl From<Transmitter> for errors::Transmitter {
    fn from(transmitter: Transmitter) -> errors::Transmitter {
        match transmitter {
            Transmitter::Engine => errors::Transmitter::Engine,
            Transmitter::BuildPlatform(id, name) => errors::Transmitter::BuildPlatform(id, name),
            Transmitter::ContainerRegistry(id, name) => errors::Transmitter::ContainerRegistry(id, name),
            Transmitter::CloudProvider(id, name) => errors::Transmitter::CloudProvider(id, name),
            Transmitter::Kubernetes(id, name) => errors::Transmitter::Kubernetes(id, name),
            Transmitter::DnsProvider(id, name) => errors::Transmitter::DnsProvider(id, name),
            Transmitter::ObjectStorage(id, name) => errors::Transmitter::ObjectStorage(id, name),
            Transmitter::Environment(id, name) => errors::Transmitter::Environment(id, name),
            Transmitter::Database(id, db_type, name) => errors::Transmitter::Database(id, db_type, name),
            Transmitter::Application(id, name) => errors::Transmitter::Application(id, name),
            Transmitter::Router(id, name) => errors::Transmitter::Router(id, name),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum Tag {
    UnsupportedInstanceType(String),
}

impl From<Tag> for errors::Tag {
    fn from(tag: Tag) -> Self {
        match tag {
            Tag::UnsupportedInstanceType(s) => errors::Tag::UnsupportedInstanceType(s),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct UserEngineError {
    provider_kind: Kind,
    organisation_id: String,
    cluster_id: String,
    execution_id: String,
    tag: Tag,
    transmitter: Transmitter,
    severity: Severity,
    stage: Stage,
    log_message: String,
    raw_message_safe: Option<String>,
    link: Option<String>,
    hint_message: Option<String>,
}

impl From<UserEngineError> for errors::UserEngineError {
    fn from(e: UserEngineError) -> Self {
        errors::UserEngineError::new(
            e.provider_kind,
            QoveryIdentifier::new(e.organisation_id),
            QoveryIdentifier::new(e.cluster_id),
            QoveryIdentifier::new(e.execution_id),
            errors::Tag::from(e.tag),
            errors::Transmitter::from(e.transmitter),
            errors::Stage::from(e.stage),
            errors::Severity::from(e.severity),
            e.log_message,
            e.raw_message_safe,
            match e.link {
                Some(url) => match Url::from_str(&url) {
                    Ok(url) => Some(url),
                    Err(_) => None,
                },
                None => None,
            },
            e.hint_message,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct EngineError {
    provider_kind: Kind,
    tag: Tag,
    organisation_id: String,
    cluster_id: String,
    execution_id: String,
    severity: Severity,
    transmitter: Transmitter,
    stage: Stage,
    qovery_log_message: String,
    user_log_message: String,
    raw_message: Option<String>,
    raw_message_safe: Option<String>,
    link: Option<String>,
    hint_message: Option<String>,
}

impl From<EngineError> for errors::EngineError {
    fn from(e: EngineError) -> Self {
        errors::EngineError::new(
            e.provider_kind,
            errors::Tag::from(e.tag),
            QoveryIdentifier::new(e.organisation_id),
            QoveryIdentifier::new(e.cluster_id),
            QoveryIdentifier::new(e.execution_id),
            errors::Stage::from(e.stage),
            errors::Transmitter::from(e.transmitter),
            errors::Severity::from(e.severity),
            e.qovery_log_message,
            e.user_log_message,
            e.raw_message,
            e.raw_message_safe,
            match e.link {
                Some(url) => match Url::from_str(&url) {
                    Ok(url) => Some(url),
                    Err(_) => None,
                },
                None => None,
            },
            e.hint_message,
        )
    }
}
