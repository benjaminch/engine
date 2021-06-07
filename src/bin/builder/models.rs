use crate::consts;
use crate::errors;
use crate::errors::BuilderError;
use crate::models;
use crate::utilities;
use chrono::Duration;
use qovery_engine::error::{EngineError, EngineErrorCause, SimpleError, SimpleErrorKind};
use qovery_engine::{cmd, fs, git};
use std::borrow::Cow;
use std::{env, fmt, path};
use sysinfo::{Disk, DiskExt, SystemExt};

pub struct Builder {
    running_mode: models::RunningMode,
}

impl Builder {
    pub fn new(running_mode: models::RunningMode) -> Builder {
        Builder { running_mode }
    }

    pub fn process(
        &self,
        application_id: String,
        force_build: bool,
        execution_id: String,
        workspace_dir: String,
        repository_root_path: String,
        repository_url: String,
        repository_commit_id: String,
        git_credentials: Option<git::Credentials>,
        docker_build_options: Vec<String>,
        docker_environment_variables: Vec<EnvironmentVariable>,
        docker_tcp_socket: Option<String>,
        docker_dockerfile_path: Option<String>,
        image_name: String,
        image_tag: String,
        image_registry_name: Option<String>,
        image_registry_secret: Option<String>,
        image_registry_url: Option<String>,
    ) -> Result<BuilderResult, errors::BuilderError> {
        // create task to be processed
        let task_not_started = BuilderTask::<NotStarted>::new(
            application_id,
            force_build,
            execution_id,
            workspace_dir,
            repository_root_path,
            repository_url,
            repository_commit_id,
            git_credentials,
            docker_build_options,
            docker_environment_variables,
            docker_tcp_socket,
            docker_dockerfile_path,
            image_name,
            image_tag,
            image_registry_name,
            image_registry_secret,
            image_registry_url,
        );

        // check build environment
        let task_build_environment_check = BuilderTask::<BuildEnvironmentCheck>::from(task_not_started);

        Ok(BuilderResult::new())
    }
}

struct BuilderTask<'a, S>
where
    S: BuilderStep,
{
    state: Box<S>,
    err: Option<errors::BuilderError<'a>>,
    application_id: String,
    force_build: bool,
    execution_id: String,
    workspace_dir: String,
    repository_root_path: String,
    repository_url: String,
    repository_commit_id: String,
    git_credentials: Option<git::Credentials>,
    docker_build_options: Vec<String>,
    docker_environment_variables: Vec<EnvironmentVariable>,
    docker_tcp_socket: Option<String>,
    docker_dockerfile_path: Option<String>,
    image_name: String,
    image_tag: String,
    // registry name where the image has been pushed: Optional
    image_registry_name: Option<String>,
    // registry secret to pull image: Optional
    image_registry_secret: Option<String>,
    // complete registry URL where the image has been pushed
    image_registry_url: Option<String>,
}

impl<'a> BuilderTask<'a, NotStarted> {
    fn new(
        application_id: String,
        force_build: bool,
        execution_id: String,
        workspace_dir: String,
        repository_root_path: String,
        repository_url: String,
        repository_commit_id: String,
        git_credentials: Option<git::Credentials>,
        docker_build_options: Vec<String>,
        docker_environment_variables: Vec<EnvironmentVariable>,
        docker_tcp_socket: Option<String>,
        docker_dockerfile_path: Option<String>,
        image_name: String,
        image_tag: String,
        image_registry_name: Option<String>,
        image_registry_secret: Option<String>,
        image_registry_url: Option<String>,
    ) -> Self {
        BuilderTask {
            err: None,
            state: Box::new(NotStarted),
            application_id,
            force_build,
            execution_id,
            workspace_dir,
            repository_root_path,
            repository_url,
            repository_commit_id,
            git_credentials,
            docker_build_options,
            docker_environment_variables,
            docker_tcp_socket,
            docker_dockerfile_path,
            image_name,
            image_tag,
            image_registry_name,
            image_registry_secret,
            image_registry_url,
        }
    }
}

impl<'a, S: BuilderStep> BuilderTask<'a, S> {
    fn set_errored(&mut self, err: errors::BuilderError<'a>)
    where
        S: Clone,
    {
        self.state = self.state.clone();
        self.err = Some(err);
    }
}

pub trait BuilderStep {}

#[derive(Clone)]
struct NotStarted;

impl BuilderStep for NotStarted {}

#[derive(Clone)]
struct BuildEnvironmentCheck;

impl BuilderStep for BuildEnvironmentCheck {}

impl<'a> From<BuilderTask<'a, NotStarted>> for BuilderTask<'a, BuildEnvironmentCheck> {
    fn from(task: BuilderTask<'a, NotStarted>) -> BuilderTask<'a, BuildEnvironmentCheck> {
        info!("checking building environment");

        let mut task_to_update = task;

        if !cmd::utilities::does_binary_exist("docker") {
            task_to_update.set_errored(errors::BuilderError::new(
                task_to_update.execution_id.clone(),
                errors::BuilderErrorScope::BuildEnvironmentCheck,
                errors::BuilderErrorCause::Internal(Box::new(errors::BuildEnvNotValidError::new(
                    "docker binary is missing",
                ))),
            ));

            return task_to_update.into();
        }

        if !cmd::utilities::does_binary_exist("pack") {
            task_to_update.set_errored(errors::BuilderError::new(
                task_to_update.execution_id.clone(),
                errors::BuilderErrorScope::BuildEnvironmentCheck,
                errors::BuilderErrorCause::Internal(Box::new(errors::BuildEnvNotValidError::new(
                    "pack binary is missing",
                ))),
            ));

            return task_to_update.into();
        }

        task_to_update.into()
    }
}

#[derive(Clone)]
struct RepositoryCloned;

impl BuilderStep for RepositoryCloned {}

impl<'a> From<BuilderTask<'a, BuildEnvironmentCheck>> for BuilderTask<'a, RepositoryCloned> {
    fn from(task: BuilderTask<'a, BuildEnvironmentCheck>) -> BuilderTask<'a, RepositoryCloned> {
        let mut task_to_update = task;
        let repository_git_path = task_to_update.workspace_dir.clone();

        info!(
            "Cloning repository: {} to {}",
            task_to_update.repository_url, repository_git_path,
        );

        let git_clone = git::clone(
            task_to_update.repository_url.as_str(),
            repository_git_path,
            &task_to_update.git_credentials,
        );

        if let Err(e) = git_clone {
            let message = format!(
                "Error while cloning repository {}. Error: {:?}",
                &task_to_update.repository_url, e
            );
            error!("{}", message);

            task_to_update.set_errored(errors::BuilderError::new(
                task_to_update.execution_id.clone(),
                errors::BuilderErrorScope::RepositoryCloning,
                errors::BuilderErrorCause::Internal(Box::new(errors::ProjectRepositoryCloningError::new(Box::new(e)))),
            ));

            return task_to_update.into();
        }

        // git checkout to given commit
        let repo = git_clone.unwrap();
        let commit_id = task_to_update.repository_commit_id.clone();

        if let Err(e) = git::checkout(&repo, commit_id.as_str(), task_to_update.repository_url.as_str()) {
            let message = format!(
                "Error while git checkout repository {} with commit id {}. Error: {:?}",
                task_to_update.repository_url, commit_id, e
            );
            error!("{}", message);

            task_to_update.set_errored(errors::BuilderError::new(
                task_to_update.execution_id.clone(),
                errors::BuilderErrorScope::RepositoryCloning,
                errors::BuilderErrorCause::Internal(Box::new(errors::ProjectRepositoryCloningError::new(Box::new(e)))),
            ));

            return task_to_update.into();
        }

        // git checkout submodules
        if let Err(e) = git::checkout_submodules(&repo) {
            let message = format!(
                "Error while checkout submodules from repository {}. Error: {:?}",
                task_to_update.repository_url, e
            );
            error!("{}", message);

            task_to_update.set_errored(errors::BuilderError::new(
                task_to_update.execution_id.clone(),
                errors::BuilderErrorScope::RepositoryCloning,
                errors::BuilderErrorCause::Internal(Box::new(errors::ProjectRepositoryCloningError::new(Box::new(e)))),
            ));

            return task_to_update.into();
        }

        task_to_update.into()
    }
}

struct ProjectBuilt {
    force_build: bool,
    docker_build_options: Vec<String>,
    docker_environment_variables: Vec<EnvironmentVariable>,
    docker_tcp_socket: Option<String>,
    docker_dockerfile_path: Option<String>,
    image_name: String,
    image_tag: String,
    image_registry_name: Option<String>,
    image_registry_secret: Option<String>,
    image_registry_url: Option<String>,
}

impl ProjectBuilt {
    fn new(
        force_build: bool,
        docker_build_options: Vec<String>,
        docker_environment_variables: Vec<EnvironmentVariable>,
        docker_tcp_socket: Option<String>,
        docker_dockerfile_path: Option<String>,
        image_name: String,
        image_tag: String,
        image_registry_name: Option<String>,
        image_registry_secret: Option<String>,
        image_registry_url: Option<String>,
    ) -> ProjectBuilt {
        ProjectBuilt {
            force_build,
            docker_build_options,
            docker_environment_variables,
            docker_tcp_socket,
            docker_dockerfile_path,
            image_name,
            image_tag,
            image_registry_name,
            image_registry_secret,
            image_registry_url,
        }
    }

    fn get_docker_host_envs(&self) -> Vec<(&str, &str)> {
        match &self.docker_tcp_socket {
            Some(tcp_socket) => vec![("DOCKER_HOST", tcp_socket.as_str())],
            None => vec![],
        }
    }

    fn image_name_with_tag(&self) -> String {
        format!("{}:{}", self.image_name, self.image_tag)
    }

    pub fn docker_build_options(&self) -> Option<Vec<String>> {
        if !&self.docker_build_options.is_empty() {
            return Some(
                self.docker_build_options
                    .clone()
                    .iter()
                    .map(|b| b.split(' ').map(|x| x.to_string()).collect())
                    .collect(),
            );
        }

        None
    }

    fn build_image_with_docker(
        &self,
        dockerfile_complete_path: &str,
        into_dir_docker_style: &str,
        env_var_args: Vec<String>,
        use_build_cache: bool,
    ) -> Result<ProjectBuildingResult, errors::ProjectBuildingError> {
        let mut docker_args = if !use_build_cache {
            vec!["build", "--no-cache"]
        } else {
            vec!["build"]
        };

        let docker_build_options = &self.docker_build_options();
        if let Some(args) = docker_build_options {
            for v in args.iter() {
                docker_args.push(String::as_str(v));
            }
        }

        let name_with_tag = self.image_name_with_tag();

        docker_args.extend(vec!["-f", dockerfile_complete_path, "-t", name_with_tag.as_str()]);

        let mut docker_args = if env_var_args.is_empty() {
            docker_args
        } else {
            let mut build_args = vec![];
            env_var_args.iter().for_each(|x| {
                build_args.push("--build-arg");
                build_args.push(x.as_str());
            });

            docker_args.extend(build_args);
            docker_args
        };

        docker_args.push(into_dir_docker_style);

        // docker build
        let exit_status = cmd::utilities::exec_with_envs_and_output(
            "docker",
            docker_args,
            self.get_docker_host_envs(),
            |line| {
                let line_string = line.unwrap();
                info!("{}", line_string.as_str());
            },
            |line| {
                let line_string = line.unwrap();
                error!("{}", line_string.as_str());
            },
            Duration::minutes(consts::BUILD_DURATION_TIMEOUT_MIN),
        );

        match exit_status {
            Ok(_) => Ok(ProjectBuildingResult),
            Err(e) => Err(
                errors::ProjectBuildingError::new(
                    "Docker error while building container image. Error: {:?}",
                    Some("It looks like there is something wrong in your Dockerfile. Try run locally using `qovery run` or build with `docker build --no-cache`"),
                    Box::new(e),
                ))
        }
    }

    fn build_image_with_buildpacks(
        &self,
        into_dir_docker_style: &str,
        env_var_args: Vec<String>,
        use_build_cache: bool,
    ) -> Result<ProjectBuildingResult, errors::ProjectBuildingError> {
        let name_with_tag = self.image_name_with_tag();

        let mut exit_status: Result<Vec<String>, SimpleError> =
            Err(SimpleError::new(SimpleErrorKind::Other, Some("no builder names")));

        for builder_name in consts::BUILDPACKS_BUILDERS.iter() {
            let mut buildpacks_args = if !use_build_cache {
                vec!["build", name_with_tag.as_str(), "--clear-cache"]
            } else {
                vec!["build", name_with_tag.as_str()]
            };

            let docker_build_options = &self.docker_build_options();
            if let Some(args) = docker_build_options {
                for v in args.iter() {
                    buildpacks_args.push(String::as_str(v));
                }
            }

            buildpacks_args.extend(vec!["--path", into_dir_docker_style]);

            let mut buildpacks_args = if env_var_args.is_empty() {
                buildpacks_args
            } else {
                let mut build_args = vec![];

                env_var_args.iter().for_each(|x| {
                    build_args.push("--env");
                    build_args.push(x.as_str());
                });

                buildpacks_args.extend(build_args);
                buildpacks_args
            };

            buildpacks_args.push("-B");
            buildpacks_args.push(builder_name);

            // buildpacks build
            exit_status = cmd::utilities::exec_with_envs_and_output(
                "pack",
                buildpacks_args,
                self.get_docker_host_envs(),
                |line| {
                    let line_string = line.unwrap();
                    info!("{}", line_string.as_str());
                },
                |line| {
                    let line_string = line.unwrap();
                    error!("{}", line_string.as_str());
                },
                Duration::minutes(consts::BUILD_DURATION_TIMEOUT_MIN),
            );

            if exit_status.is_ok() {
                // quit now if the builder successfully build the app
                break;
            }
        }

        match exit_status {
            Ok(_) => Ok(ProjectBuildingResult),
            Err(e) => {
                warn!("{:?}", e);

                Err(errors::ProjectBuildingError::new(
                        "Qovery can't build your container image with one of the following builders: [heroku/buildpacks:20]. \
                    Please do provide a valid Dockerfile to build your application or contact the support.",
                    Some("None builders supports your application can't be built without providing a Dockerfile"),
                    Box::new(e),
                ))
            }
        }
    }
}

impl BuilderStep for ProjectBuilt {}

impl<'a> From<BuilderTask<'a, RepositoryCloned>> for BuilderTask<'a, ProjectBuilt> {
    fn from(task: BuilderTask<'a, RepositoryCloned>) -> BuilderTask<'a, ProjectBuilt> {
        let project_built = ProjectBuilt {
            force_build: task.force_build.clone(),
            docker_build_options: task.docker_build_options.clone(),
            docker_environment_variables: task
                .docker_environment_variables
                .iter()
                .map(|e| EnvironmentVariable {
                    key: e.key.clone(),
                    value: e.value.clone(),
                })
                .collect(),
            docker_tcp_socket: task.docker_tcp_socket.clone(),
            docker_dockerfile_path: task.docker_dockerfile_path.clone(),
            image_name: task.image_name.clone(),
            image_tag: task.image_tag.clone(),
            image_registry_name: task.image_registry_name.clone(),
            image_registry_secret: task.image_registry_secret.clone(),
            image_registry_url: task.image_registry_url.clone(),
        };
        let mut task_to_update = task;

        info!("LocalDocker.build() called for {}", task_to_update.image_name);

        // TODO(benjaminch): Handle build cache here

        let mut disable_build_cache = false;
        let mut env_var_args: Vec<String> = Vec::with_capacity(task_to_update.docker_environment_variables.len());

        for ev in &task_to_update.docker_environment_variables {
            if ev.key == "QOVERY_DISABLE_BUILD_CACHE" && ev.value.to_lowercase() == "true" {
                // this is a special flag to disable build cache dynamically
                // -- do not pass this env var key/value to as build parameter
                disable_build_cache = true;
            } else {
                env_var_args.push(format!("{}={}", ev.key, ev.value));
            }
        }

        // ensure docker_path is a mounted volume, otherwise ignore because it's not what Qovery does in production
        // ex: this cause regular cleanup on CI, leading to random tests errors
        match env::var_os("CI") {
            Some(_) => info!("CI environment variable found, no docker prune will be made"),
            None => {
                // ensure there is enough disk space left before building a new image
                let docker_path_string = "/var/lib/docker";
                let docker_path = path::Path::new(docker_path_string);

                // get system info
                let mut system = sysinfo::System::new_all();
                system.refresh_all();

                for disk in system.get_disks() {
                    if disk.get_mount_point() == docker_path {
                        match utilities::check_docker_space_usage_and_clean(disk, project_built.get_docker_host_envs())
                        {
                            Ok(msg) => info!("{:?}", msg),
                            Err(e) => error!("{:?}", e.message),
                        }
                        break;
                    };
                }
            }
        }

        let build_context_path = format!(
            "{}/{}/.",
            task_to_update.repository_root_path.as_str(),
            task_to_update.repository_root_path
        );

        // If no Dockerfile specified, we should use BuildPacks
        let result = if task_to_update.docker_dockerfile_path.is_some() {
            // build container from the provided Dockerfile
            let dockerfile_relative_path = task_to_update.docker_dockerfile_path.as_ref().unwrap();
            let dockerfile_normalized_path = match dockerfile_relative_path.trim() {
                "" | "." | "/" | "/." | "./" | "Dockerfile" => "Dockerfile",
                dockerfile_root_path => dockerfile_root_path,
            };

            let dockerfile_relative_path =
                format!("{}/{}", task_to_update.repository_root_path, dockerfile_normalized_path);
            let dockerfile_absolute_path = format!(
                "{}/{}",
                task_to_update.repository_root_path.as_str(),
                dockerfile_relative_path
            );

            // If the dockerfile does not exist, abort
            if !path::Path::new(dockerfile_absolute_path.as_str()).exists() {
                warn!("Dockerfile not found under {}", dockerfile_absolute_path);

                task_to_update.set_errored(errors::BuilderError::new(
                    task_to_update.execution_id.clone(),
                    errors::BuilderErrorScope::ImageBuilding,
                    errors::BuilderErrorCause::Internal(Box::new(errors::DockerFileNotFoundError::new())),
                ));

                return task_to_update.into();
            }

            project_built.build_image_with_docker(
                dockerfile_absolute_path.as_str(),
                build_context_path.as_str(),
                env_var_args,
                !disable_build_cache,
            )
        } else {
            // build container with Buildpacks
            project_built.build_image_with_buildpacks(build_context_path.as_str(), env_var_args, !disable_build_cache)
        };

        task_to_update.into()
    }
}

#[derive(Clone)]
struct Done;

impl BuilderStep for Done {}

pub enum RunningMode {
    OnDemand,
    Daemon,
}

pub struct EnvironmentVariable {
    key: String,
    value: String,
}

pub struct ProjectRepositoryCloningResult;

pub struct ProjectBuildingResult;

pub struct BuilderResult {
    project_repository_cloning_result: Option<ProjectRepositoryCloningResult>,
}

impl BuilderResult {
    pub fn new() -> BuilderResult {
        BuilderResult {
            project_repository_cloning_result: None,
        }
    }
}
