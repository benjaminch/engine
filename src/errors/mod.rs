pub mod io;

extern crate url;

use crate::cloud_provider::Kind;
use crate::error::{EngineErrorCause, EngineErrorScope, LegacyEngineError};
use crate::models::QoveryIdentifier;
use url::Url;

pub struct SimpleError {
    message: String,
    message_safe: String,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub enum Stage {
    Infrastructure(InfrastructureStep),
    Environment(EnvironmentStep),
}

#[derive(Debug, Clone)]
pub enum InfrastructureStep {
    Instantiate,
    Create,
    Pause,
    Upgrade,
    Delete,
}

#[derive(Debug, Clone)]
pub enum EnvironmentStep {
    Build,
    Deploy,
    Update,
    Delete,
}

type TranmsmitterId = String;
type TransmitterName = String;
type TransmitterType = String;

#[derive(Debug, Clone)]
pub enum Transmitter {
    Engine,
    BuildPlatform(TranmsmitterId, TransmitterName),
    ContainerRegistry(TranmsmitterId, TransmitterName),
    CloudProvider(TranmsmitterId, TransmitterName),
    Kubernetes(TranmsmitterId, TransmitterName),
    DnsProvider(TranmsmitterId, TransmitterName),
    ObjectStorage(TranmsmitterId, TransmitterName),
    Environment(TranmsmitterId, TransmitterName),
    Database(TranmsmitterId, TransmitterType, TransmitterName),
    Application(TranmsmitterId, TransmitterName),
    Router(TranmsmitterId, TransmitterName),
}

#[derive(Debug, Clone)]
pub enum Tag {
    UnsupportedInstanceType(String),
}

impl SimpleError {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn message_safe(&self) -> &str {
        &self.message_safe
    }

    pub fn new_from_safe_message(message: String) -> Self {
        SimpleError::new(message.clone(), message)
    }

    pub fn new(message: String, message_safe: String) -> Self {
        SimpleError { message, message_safe }
    }
}

#[derive(Debug, Clone)]
pub struct UserEngineError {
    provider_kind: Kind,
    organisation_id: QoveryIdentifier,
    cluster_id: QoveryIdentifier,
    execution_id: QoveryIdentifier,
    tag: Tag,
    transmitter: Transmitter,
    stage: Stage,
    severity: Severity,
    log_message: String,
    raw_message_safe: Option<String>,
    link: Option<Url>,
    hint_message: Option<String>,
}

impl UserEngineError {
    pub fn new(
        provider_kind: Kind,
        organisation_id: QoveryIdentifier,
        cluster_id: QoveryIdentifier,
        execution_id: QoveryIdentifier,
        tag: Tag,
        transmitter: Transmitter,
        stage: Stage,
        severity: Severity,
        log_message: String,
        raw_message_safe: Option<String>,
        link: Option<Url>,
        hint_message: Option<String>,
    ) -> Self {
        UserEngineError {
            provider_kind,
            organisation_id,
            cluster_id,
            execution_id,
            tag,
            transmitter,
            stage,
            severity,
            log_message,
            raw_message_safe,
            link,
            hint_message,
        }
    }
}

impl From<EngineError> for UserEngineError {
    fn from(error: EngineError) -> Self {
        UserEngineError::new(
            error.provider_kind,
            error.organisation_id,
            error.cluster_id,
            error.execution_id,
            error.tag,
            error.transmitter,
            error.stage,
            error.severity,
            error.user_log_message,
            error.raw_message_safe,
            error.link,
            error.hint_message,
        )
    }
}

#[derive(Debug, Clone)]
pub struct EngineError {
    provider_kind: Kind,
    tag: Tag,
    organisation_id: QoveryIdentifier,
    cluster_id: QoveryIdentifier,
    execution_id: QoveryIdentifier,
    stage: Stage,
    transmitter: Transmitter,
    severity: Severity,
    qovery_log_message: String,
    user_log_message: String,
    raw_message: Option<String>,
    raw_message_safe: Option<String>,
    link: Option<Url>,
    hint_message: Option<String>,
}

impl EngineError {
    pub fn provider_kind(&self) -> &Kind {
        &self.provider_kind
    }
    pub fn tag(&self) -> &Tag {
        &self.tag
    }
    pub fn execution_id(&self) -> &QoveryIdentifier {
        &self.execution_id
    }
    pub fn stage(&self) -> &Stage {
        &self.stage
    }
    pub fn severity(&self) -> &Severity {
        &self.severity
    }
    pub fn qovery_log_message(&self) -> &str {
        &self.qovery_log_message
    }
    pub fn user_log_message(&self) -> &str {
        &self.user_log_message
    }
    pub fn raw_message(&self) -> Option<String> {
        self.raw_message.clone()
    }
    pub fn raw_message_safe(&self) -> Option<String> {
        self.raw_message_safe.clone()
    }
    pub fn link(&self) -> &Option<Url> {
        &self.link
    }
    pub fn hint_message(&self) -> &Option<String> {
        &self.hint_message
    }

    fn new(
        provider_kind: Kind,
        tag: Tag,
        execution_id: QoveryIdentifier,
        organisation_id: QoveryIdentifier,
        cluster_id: QoveryIdentifier,
        stage: Stage,
        transmitter: Transmitter,
        severity: Severity,
        qovery_log_message: String,
        user_log_message: String,
        raw_message: Option<String>,
        raw_message_safe: Option<String>,
        link: Option<Url>,
        hint_message: Option<String>,
    ) -> Self {
        EngineError {
            provider_kind,
            tag,
            stage,
            transmitter,
            organisation_id,
            cluster_id,
            execution_id,
            severity,
            qovery_log_message,
            user_log_message,
            raw_message,
            raw_message_safe,
            link,
            hint_message,
        }
    }

    pub fn to_user_error(self) -> UserEngineError {
        UserEngineError::from(self)
    }

    pub fn to_legacy_engine_error(self) -> LegacyEngineError {
        LegacyEngineError::new(
            EngineErrorCause::Internal,
            EngineErrorScope::from(self.transmitter),
            self.execution_id.to_string(),
            self.raw_message_safe,
        )
    }

    pub fn new_unsupported_instance_type(
        provider_kind: Kind,
        organisation_id: QoveryIdentifier,
        cluster_id: QoveryIdentifier,
        execution_id: QoveryIdentifier,
        stage: Stage,
        requested_instance_type: &str,
        raw_message: Option<String>,
    ) -> EngineError {
        let message = format!("`{}` instance type is not supported", requested_instance_type);
        EngineError::new(
            provider_kind,
            Tag::UnsupportedInstanceType(requested_instance_type.to_string()),
            organisation_id,
            cluster_id.clone(),
            execution_id,
            stage,
            Transmitter::Kubernetes(cluster_id.to_string(), cluster_id.to_string()),
            Severity::Critical,
            message.to_string(),
            message,
            raw_message.clone(),
            raw_message, // there is no unsafe data in this message
            None,        // TODO(documentation): Create a page entry to details this error
            Some("Selected instance type is not supported, please check provider's documentation.".to_string()),
        )
    }
}
