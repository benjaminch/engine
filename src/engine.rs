use std::borrow::Borrow;

use crate::build_platform::BuildPlatform;
use crate::cloud_provider::CloudProvider;
use crate::container_registry::ContainerRegistry;
use crate::dns_provider::DnsProvider;
use crate::error::LegacyEngineError;
use crate::logs::LogManager;
use crate::models::Context;
use crate::session::Session;

pub struct Engine {
    log_manager: &'static LogManager<'static>,
    context: Context,
    build_platform: Box<dyn BuildPlatform>,
    container_registry: Box<dyn ContainerRegistry>,
    cloud_provider: Box<dyn CloudProvider>,
    dns_provider: Box<dyn DnsProvider>,
}

impl Engine {
    pub fn new(
        log_manager: &'static LogManager,
        context: Context,
        build_platform: Box<dyn BuildPlatform>,
        container_registry: Box<dyn ContainerRegistry>,
        cloud_provider: Box<dyn CloudProvider>,
        dns_provider: Box<dyn DnsProvider>,
    ) -> Engine {
        Engine {
            log_manager,
            context,
            build_platform,
            container_registry,
            cloud_provider,
            dns_provider,
        }
    }
}

impl<'a> Engine {
    pub fn log_manager(&self) -> &'a LogManager<'static> {
        &self.log_manager
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn build_platform(&self) -> &dyn BuildPlatform {
        self.build_platform.borrow()
    }

    pub fn container_registry(&self) -> &dyn ContainerRegistry {
        self.container_registry.borrow()
    }

    pub fn cloud_provider(&self) -> &dyn CloudProvider {
        self.cloud_provider.borrow()
    }

    pub fn dns_provider(&self) -> &dyn DnsProvider {
        self.dns_provider.borrow()
    }

    pub fn is_valid(&self) -> Result<(), LegacyEngineError> {
        self.build_platform.is_valid()?;
        self.container_registry.is_valid()?;
        self.cloud_provider.is_valid()?;
        self.dns_provider.is_valid()?;

        Ok(())
    }

    /// check and init the connection to all services
    pub fn session(&'a self) -> Result<Session<'a>, LegacyEngineError> {
        match self.is_valid() {
            Ok(_) => Ok(Session::<'a> { engine: self }),
            Err(err) => Err(err),
        }
    }
}
