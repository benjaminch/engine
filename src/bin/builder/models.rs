use crate::consts;
use crate::errors;
use crate::models;
use crate::utilities;
use chrono::Duration;
use qovery_engine::error::{SimpleError, SimpleErrorKind};
use qovery_engine::{cmd, git};
use qovery_engine::container_registry;
use std::rc::Rc;
use std::{env, path};
use sysinfo::{DiskExt, SystemExt};

pub struct Builder {
    running_mode: models::RunningMode,
}

impl<'a> Builder {
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
        image_registry_kind: container_registry::Kind,
        image_registry_name: Option<String>,
        image_registry_secret: Option<String>,
        image_registry_url: Option<String>,
    ) -> Result<(), ()> {
        // create task to be processed
        let task = BuilderTask::<NotStarted>::new(
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
            image_registry_kind,
            image_registry_name,
            image_registry_secret,
            image_registry_url,
        );

        // check build environment
        let task = BuilderTask::<BuildEnvironmentChecked>::from(task);
        if let Some(e) = task.get_error() {
            error!("{}", e);
            return Err(());
        }

        // clone repository
        let task = BuilderTask::<RepositoryCloned>::from(task);
        if let Some(e) = task.get_error() {
            error!("{}", e);
            return Err(());
        }

        // build project
        let task = BuilderTask::<ProjectBuilt>::from(task);
        if let Some(e) = task.get_error() {
            error!("{}", e);
            return Err(());
        }

        // push image to image registry
        let task = BuilderTask::<ImagePushed>::from(task);
        if let Some(e) = task.get_error() {
            error!("{}", e);
            return Err(());
        }

        Ok(())
    }
}

#[derive(Clone)]
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
    image_registry_kind: container_registry::Kind,
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
        image_registry_kind: container_registry::Kind,
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
            image_registry_kind,
            image_registry_name,
            image_registry_secret,
            image_registry_url,
        }
    }
}

impl<'a, S> BuilderTask<'a, S>
where
    S: BuilderStep,
{
    fn get_workspace_full_path(&self) -> String {
        self.workspace_dir.clone()
    }

    fn get_repository_full_path(&self) -> String {
        format!("{}/{}", self.workspace_dir, self.repository_root_path)
    }

    fn get_dockerfile_full_path(&self) -> Option<String> {
        match &self.docker_dockerfile_path {
            Some(dockerfile_path) => Some(format!("{}/{}", self.get_repository_full_path(), dockerfile_path)),
            None => None,
        }
    }

    fn get_error(&self) -> Option<&errors::BuilderError> {
        self.err.as_ref()
    }

    fn to_state<T: BuilderStep>(task: BuilderTask<S>, step: Box<T>) -> BuilderTask<T> {
        BuilderTask {
            state: step,
            err: None,
            application_id: task.application_id.clone(),
            force_build: task.force_build,
            execution_id: task.execution_id.clone(),
            workspace_dir: task.workspace_dir.clone(),
            repository_root_path: task.repository_root_path.clone(),
            repository_url: task.repository_url.clone(),
            repository_commit_id: task.repository_commit_id.clone(),
            git_credentials: task.git_credentials.clone(),
            docker_build_options: task.docker_build_options.clone(),
            docker_environment_variables: task.docker_environment_variables.clone(),
            docker_tcp_socket: task.docker_tcp_socket.clone(),
            docker_dockerfile_path: task.docker_dockerfile_path.clone(),
            image_name: task.image_name.clone(),
            image_tag: task.image_tag.clone(),
            image_registry_kind: task.image_registry_kind.clone(),
            image_registry_name: task.image_registry_name.clone(),
            image_registry_secret: task.image_registry_secret.clone(),
            image_registry_url: task.image_registry_url.clone(),
        }
    }

    fn to_errored(task: BuilderTask<S>, err: errors::BuilderError<'a>) -> BuilderTask<'a, S>
    where
        S: Clone,
    {
        BuilderTask {
            state: task.state.clone(),
            err: Some(err),
            application_id: task.application_id.clone(),
            force_build: task.force_build,
            execution_id: task.execution_id.clone(),
            workspace_dir: task.workspace_dir.clone(),
            repository_root_path: task.repository_root_path.clone(),
            repository_url: task.repository_url.clone(),
            repository_commit_id: task.repository_commit_id.clone(),
            git_credentials: task.git_credentials.clone(),
            docker_build_options: task.docker_build_options.clone(),
            docker_environment_variables: task.docker_environment_variables.clone(),
            docker_tcp_socket: task.docker_tcp_socket.clone(),
            docker_dockerfile_path: task.docker_dockerfile_path.clone(),
            image_name: task.image_name.clone(),
            image_tag: task.image_tag.clone(),
            image_registry_kind: task.image_registry_kind.clone(),
            image_registry_name: task.image_registry_name.clone(),
            image_registry_secret: task.image_registry_secret.clone(),
            image_registry_url: task.image_registry_url.clone(),
        }
    }
}

pub trait BuilderStep {}

#[derive(Clone)]
struct NotStarted;

impl BuilderStep for NotStarted {}

#[derive(Clone)]
struct BuildEnvironmentChecked;

impl BuilderStep for BuildEnvironmentChecked {}

impl<'a> From<BuilderTask<'a, NotStarted>> for BuilderTask<'a, BuildEnvironmentChecked> {
    fn from(task: BuilderTask<'a, NotStarted>) -> BuilderTask<'a, BuildEnvironmentChecked> {
        info!("checking building environment");

        let updated_task = BuilderTask::to_state(task.clone(), Box::new(BuildEnvironmentChecked));

        if !cmd::utilities::does_binary_exist("docker") {
            return BuilderTask::to_errored(
                updated_task.clone(),
                errors::BuilderError::new(
                    task.execution_id.clone(),
                    errors::BuilderErrorScope::BuildEnvironmentCheck,
                    errors::BuilderErrorCause::Internal(Rc::new(errors::BuildEnvNotValidError::new(String::from(
                        "docker binary is missing",
                    )))),
                    Some(String::from("docker binary is missing")),
                    Some(String::from("docker binary is missing")),
                ),
            );
        }

        if !cmd::utilities::does_binary_exist("pack") {
            if !cmd::utilities::does_binary_exist("pack") {
                return BuilderTask::to_errored(
                    updated_task.clone(),
                    errors::BuilderError::new(
                        task.execution_id.clone(),
                        errors::BuilderErrorScope::BuildEnvironmentCheck,
                        errors::BuilderErrorCause::Internal(Rc::new(errors::BuildEnvNotValidError::new(String::from(
                            "docker binary is missing",
                        )))),
                        Some(String::from("pack binary is missing")),
                        Some(String::from("pack binary is missing")),
                    ),
                );
            }
        }

        updated_task
    }
}

#[derive(Clone)]
struct RepositoryCloned;

impl BuilderStep for RepositoryCloned {}

impl<'a> From<BuilderTask<'a, BuildEnvironmentChecked>> for BuilderTask<'a, RepositoryCloned> {
    fn from(task: BuilderTask<'a, BuildEnvironmentChecked>) -> BuilderTask<'a, RepositoryCloned> {
        let repository_git_path = task.get_repository_full_path();
        let updated_task = BuilderTask::to_state(task.clone(), Box::new(RepositoryCloned));

        info!("Cloning repository: {} to {}", task.repository_url, repository_git_path);

        let git_clone = git::clone(task.repository_url.as_str(), repository_git_path, &task.git_credentials);

        if let Err(e) = git_clone {
            let message = format!(
                "Error while cloning repository {}. Error: {:?}",
                &task.repository_url, e
            );
            error!("{}", message);

            return BuilderTask::to_errored(
                updated_task.clone(),
                errors::BuilderError::new(
                    task.execution_id.clone(),
                    errors::BuilderErrorScope::RepositoryCloning,
                    errors::BuilderErrorCause::Internal(Rc::new(errors::ProjectRepositoryCloningError::new(
                        task.repository_url.clone(),
                        Box::new(e),
                    ))),
                    Some(message.clone()),
                    Some(message),
                ),
            );
        }

        // git checkout to given commit
        let repo = git_clone.unwrap();
        let commit_id = task.repository_commit_id.clone();

        if let Err(e) = git::checkout(&repo, commit_id.as_str(), task.repository_url.as_str()) {
            let message = format!(
                "Error while git checkout repository {} with commit id {}. Error: {:?}",
                task.repository_url, commit_id, e
            );
            error!("{}", message);

            return BuilderTask::to_errored(
                updated_task.clone(),
                errors::BuilderError::new(
                    task.execution_id.clone(),
                    errors::BuilderErrorScope::RepositoryCloning,
                    errors::BuilderErrorCause::Internal(Rc::new(errors::ProjectRepositoryCloningError::new(
                        task.repository_url.clone(),
                        Box::new(e),
                    ))),
                    Some(message.clone()),
                    Some(message),
                ),
            );
        }

        // git checkout submodules
        if let Err(e) = git::checkout_submodules(&repo) {
            let message = format!(
                "Error while checkout submodules from repository {}. Error: {:?}",
                task.repository_url, e
            );
            error!("{}", message);

            return BuilderTask::to_errored(
                updated_task.clone(),
                errors::BuilderError::new(
                    task.execution_id.clone(),
                    errors::BuilderErrorScope::RepositoryCloning,
                    errors::BuilderErrorCause::Internal(Rc::new(errors::ProjectRepositoryCloningError::new(
                        task.repository_url.clone(),
                        Box::new(e),
                    ))),
                    Some(message.clone()),
                    Some(message),
                ),
            );
        }

        updated_task
    }
}

#[derive(Clone)]
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
                    String::from("Docker error while building container image. Error: {:?}"),
                    Some(String::from("It looks like there is something wrong in your Dockerfile. Try run locally using `qovery run` or build with `docker build --no-cache`")),
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
                    format!(
                        "Qovery can't build your container image {} with one of the following builders: {}. \
                    Please do provide a valid Dockerfile to build your application or contact the support.",
                        self.image_name,
                        consts::BUILDPACKS_BUILDERS.join(", "),
                    ),
                    Some(String::from(
                        "None builders supports your application can't be built without providing a Dockerfile",
                    )),
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
        let updated_task = BuilderTask::to_state(task.clone(), Box::new(project_built.clone()));

        info!("LocalDocker.build() called for {}", task.image_name);

        // TODO(benjaminch): Handle build cache here

        let mut disable_build_cache = false;
        let mut env_var_args: Vec<String> = Vec::with_capacity(task.docker_environment_variables.len());

        for ev in &task.docker_environment_variables {
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
                        match utilities::check_docker_space_usage_and_clean(disk, &project_built.get_docker_host_envs())
                        {
                            Ok(msg) => info!("{:?}", msg),
                            Err(e) => error!("{:?}", e.message),
                        }
                        break;
                    };
                }
            }
        }

        // If no Dockerfile specified, we should use BuildPacks
        let dockerfile_full_path = task.get_dockerfile_full_path();
        let result = if dockerfile_full_path.is_some() {
            // build container from the provided Dockerfile
            let dockerfile_full_path = dockerfile_full_path.unwrap();
            let dockerfile_full_path = dockerfile_full_path.trim();
            let dockerfile_normalized_path = match dockerfile_full_path {
                "" | "." | "/" | "/." | "./" | "Dockerfile" => "Dockerfile",
                dockerfile_root_path => dockerfile_root_path,
            };

            // If the dockerfile does not exist, abort
            if !path::Path::new(dockerfile_normalized_path).exists() {
                let message = format!("Dockerfile not found under {}", dockerfile_normalized_path);
                warn!("{}", message);

                return BuilderTask::to_errored(
                    updated_task.clone(),
                    errors::BuilderError::new(
                        task.execution_id.clone(),
                        errors::BuilderErrorScope::ImageBuilding,
                        errors::BuilderErrorCause::Internal(Rc::new(errors::DockerFileNotFoundError::new(
                            task.repository_root_path.clone(),
                            task.docker_dockerfile_path.clone().unwrap_or_default(),
                        ))),
                        Some(message.clone()),
                        Some(message),
                    ),
                );
            }

            project_built.build_image_with_docker(
                dockerfile_normalized_path,
                task.get_repository_full_path().as_str(),
                env_var_args,
                !disable_build_cache,
            )
        } else {
            // build container with Buildpacks
            project_built.build_image_with_buildpacks(
                task.get_repository_full_path().as_str(),
                env_var_args,
                !disable_build_cache,
            )
        };

        updated_task
    }
}

#[derive(Clone)]
struct ImagePushed {
    image_registry: container_registry::ContainerRegistry,
}

impl BuilderStep for ImagePushed {
    fn new(
        image_registry_kind: container_registry::Kind,
        image_registry_name: Option<String>,
        image_registry_secret: Option<String>,
        image_registry_url: Option<String>,
    ) -> ImagePushed {
        ImagePushed {
            image_registry: match image_registry_kind {
                container_registry::Kind::DockerHub => container_registry::docker_hub::DockerHub::new(),
            },
        }
    }
}

impl<'a> From<BuilderTask<'a, ProjectBuilt>> for BuilderTask<'a, ImagePushed> {
    fn from(task: BuilderTask<'a, ProjectBuilt>) -> BuilderTask<'a, ImagePushed> {
        let updated_task = BuilderTask::to_state(task.clone(), Box::new(ImagePushed));

        updated_task
    }
}

#[derive(Clone)]
struct Done;

impl BuilderStep for Done {}

pub enum RunningMode {
    OnDemand,
    Daemon,
}

#[derive(Clone)]
pub struct EnvironmentVariable {
    key: String,
    value: String,
}

pub struct ProjectRepositoryCloningResult;

pub struct ProjectBuildingResult;

pub struct PushResult;

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
