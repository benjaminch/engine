use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result};
use std::rc::Rc;

#[derive(Debug)]
pub struct StartBuildEnvError;

impl Display for StartBuildEnvError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Cannot start build task.")
    }
}

impl Error for StartBuildEnvError {}

#[derive(Debug)]
pub struct BuildEnvNotValidError {
    message: String,
}

impl BuildEnvNotValidError {
    pub fn new(message: String) -> BuildEnvNotValidError {
        BuildEnvNotValidError { message }
    }
}

impl Display for BuildEnvNotValidError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Building environment is invalid. Error: {}", self.message)
    }
}

impl Error for BuildEnvNotValidError {}

#[derive(Debug)]
pub struct DockerFileNotFoundError {
    dockerfile_path: String,
    repository_root_path: String,
}

impl DockerFileNotFoundError {
    pub fn new(repository_root_path: String, dockerfile_path: String) -> DockerFileNotFoundError {
        DockerFileNotFoundError {
            dockerfile_path,
            repository_root_path,
        }
    }
}

impl Display for DockerFileNotFoundError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "Dockerfile is not present at the spacified location: {}/{}",
            self.repository_root_path, self.dockerfile_path
        )
    }
}

impl Error for DockerFileNotFoundError {}

#[derive(Clone, Debug)]
pub enum BuilderErrorCause<'a> {
    Internal(Rc<dyn Error + 'a>),
}

#[derive(Clone, Debug)]
pub enum BuilderErrorScope {
    BuildEnvironmentCheck,
    RepositoryCloning,
    ImageBuilding,
    ImagePushing,
}

#[derive(Debug)]
pub struct ProjectRepositoryCloningError<'a> {
    error: Box<dyn Error + 'a>,
    pub repository_url: String,
}

impl<'a> ProjectRepositoryCloningError<'a> {
    pub fn new(repository_url: String, error: Box<dyn Error + 'a>) -> ProjectRepositoryCloningError {
        ProjectRepositoryCloningError { repository_url, error }
    }
}

impl<'a> Display for ProjectRepositoryCloningError<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Error cloning {}:. Error: {}", &self.repository_url, &self.error)
    }
}

impl<'a> Error for ProjectRepositoryCloningError<'a> {}

#[derive(Debug)]
pub struct ProjectBuildingError<'a> {
    error: Box<dyn Error + 'a>,
    internal_message: String,
    user_message: Option<String>,
}

impl<'a> ProjectBuildingError<'a> {
    pub fn new(
        internal_message: String,
        user_message: Option<String>,
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

#[derive(Clone)]
pub struct BuilderError<'a> {
    pub cause: BuilderErrorCause<'a>,
    pub scope: BuilderErrorScope,
    pub execution_id: String,
    pub internal_message: Option<String>,
    pub user_message: Option<String>,
}

impl<'a> BuilderError<'a> {
    pub fn new(
        execution_id: String,
        scope: BuilderErrorScope,
        cause: BuilderErrorCause<'a>,
        internal_message: Option<String>,
        user_message: Option<String>,
    ) -> BuilderError {
        BuilderError {
            execution_id,
            scope,
            cause,
            internal_message,
            user_message,
        }
    }
}

impl<'a> Display for BuilderError<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "User: {}. Internal {}: {:?}",
            &self.user_message.as_ref().unwrap_or(&String::from("no details")),
            &self.internal_message.as_ref().unwrap_or(&String::from("no details")),
            &self.cause
        )
    }
}
