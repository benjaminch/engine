use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result};

#[derive(Debug)]
pub struct StartBuildEnvError;

impl Display for StartBuildEnvError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Cannot start build task.")
    }
}

impl Error for StartBuildEnvError {}

#[derive(Debug)]
pub struct BuildEnvNotValidError<'a> {
    message: &'a str,
}

impl<'a> BuildEnvNotValidError<'a> {
    pub fn new(message: &str) -> BuildEnvNotValidError {
        BuildEnvNotValidError { message }
    }
}

impl<'a> Display for BuildEnvNotValidError<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Building environment is invalid. Error: {}", self.message)
    }
}

impl<'a> Error for BuildEnvNotValidError<'a> {}

#[derive(Debug)]
pub struct DockerFileNotFoundError;

impl<'a> DockerFileNotFoundError {
    pub fn new() -> DockerFileNotFoundError {
        DockerFileNotFoundError {}
    }
}

impl Display for DockerFileNotFoundError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Dockerfile is not present at the specified location.")
    }
}

impl Error for DockerFileNotFoundError {}

#[derive(Debug)]
pub enum BuilderErrorCause<'a> {
    Internal(Box<dyn Error + 'a>),
}

#[derive(Debug)]
pub enum BuilderErrorScope {
    BuildEnvironmentCheck,
    RepositoryCloning,
    ImageBuilding,
    ImagePushing,
}

#[derive(Debug)]
pub struct ProjectRepositoryCloningError<'a> {
    error: Box<dyn Error + 'a>,
}

impl<'a> ProjectRepositoryCloningError<'a> {
    pub fn new(error: Box<dyn Error + 'a>) -> ProjectRepositoryCloningError<'a> {
        ProjectRepositoryCloningError { error }
    }
}

impl<'a> Display for ProjectRepositoryCloningError<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Error cloning repository:. Error: {}", &self.error)
    }
}

impl<'a> Error for ProjectRepositoryCloningError<'a> {}

#[derive(Debug)]
pub struct ProjectBuildingError<'a> {
    error: Box<dyn Error + 'a>,
    internal_message: &'a str,
    user_message: Option<&'a str>,
}

impl<'a> ProjectBuildingError<'a> {
    pub fn new(
        internal_message: &'a str,
        user_message: Option<&'a str>,
        error: Box<dyn Error>,
    ) -> ProjectBuildingError<'a> {
        ProjectBuildingError {
            internal_message,
            user_message,
            error,
        }
    }
}

impl<'a> Display for ProjectBuildingError<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "Error building project: {}. Error: {}",
            &self.internal_message, &self.error
        )
    }
}

impl<'a> Error for ProjectBuildingError<'a> {}

pub struct BuilderError<'a> {
    pub cause: BuilderErrorCause<'a>,
    pub scope: BuilderErrorScope,
    pub execution_id: String,
    pub internal_message: Option<String>,
    pub user_message: Option<String>,
}

impl<'a> BuilderError<'a> {
    pub fn new(execution_id: String, scope: BuilderErrorScope, cause: BuilderErrorCause<'a>) -> BuilderError {
        BuilderError {
            execution_id,
            scope,
            cause,
            internal_message: None,
            user_message: None,
        }
    }
}

impl<'a> Display for BuilderError<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "{}: {:?}",
            &self.internal_message.as_ref().unwrap_or(&String::from("no details")),
            &self.cause
        )
    }
}
