use crate::errors::{EngineError, SimpleError};

#[derive(Debug, Clone)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum State {
    Waiting,
    Deploying,
    Pausing,
    Deleting,
    Error,
    Deployed,
    Paused,
    Deleted,
}

impl State {
    pub fn is_error(&self) -> bool {
        if let State::Error = self {
            return true;
        }

        false
    }
}

#[derive(Clone, Debug)]
pub struct EngineEvent {
    state: State,
    error: Option<EngineError>,
}

impl EngineEvent {
    pub fn new(state: State, error: Option<EngineError>) -> Self {
        EngineEvent { state, error }
    }
}

pub trait Logger {
    fn log(&self, log_level: LogLevel, event: EngineEvent) -> Result<(), SimpleError>;
    fn heartbeat_log_for_task(&self, log_level: LogLevel, event: EngineEvent, f: &dyn Fn()) -> Result<(), SimpleError>;
}

pub struct LogManager<'a> {
    loggers: Box<Vec<&'a (Logger + Sync + Send)>>,
}

impl<'a> LogManager<'a> {
    pub fn new() -> LogManager<'a> {
        LogManager {
            loggers: Box::new(Vec::new()),
        }
    }

    pub fn add_logger<L: 'a + Logger + Sync + Send>(&mut self, logger: &'a L) {
        (*self.loggers).push(logger);
    }
}

impl<'a> Logger for LogManager<'a> {
    fn log(&self, log_level: LogLevel, event: EngineEvent) -> Result<(), SimpleError> {
        for logger in self.loggers.iter() {
            // will return an error and stop execution if any logger encounters an error
            if let Err(e) = logger.log(log_level.clone(), event.clone()) {
                return Err(e);
            }
        }

        Ok(())
    }

    fn heartbeat_log_for_task(&self, log_level: LogLevel, event: EngineEvent, f: &dyn Fn()) -> Result<(), SimpleError> {
        todo!()
    }
}

pub struct StdIoLogger {}

impl StdIoLogger {
    pub fn new() -> StdIoLogger {
        StdIoLogger {}
    }
}

impl Logger for StdIoLogger {
    fn log(&self, log_level: LogLevel, event: EngineEvent) -> Result<(), SimpleError> {
        match log_level {
            LogLevel::Debug => debug!("{:?}", event),
            LogLevel::Info => info!("{:?}", event),
            LogLevel::Warning => warn!("{:?}", event),
            LogLevel::Error => error!("{:?}", event),
        };

        Ok(())
    }

    fn heartbeat_log_for_task(&self, log_level: LogLevel, event: EngineEvent, f: &dyn Fn()) -> Result<(), SimpleError> {
        todo!()
    }
}
