use crate::consts;
use chrono::Duration;
use qovery_engine::cmd;
use qovery_engine::error::SimpleError;
use sysinfo::{Disk, DiskExt, SystemExt};

pub fn check_docker_space_usage_and_clean(
    docker_path_size_info: &Disk,
    envs: &Vec<(&str, &str)>,
) -> Result<String, SimpleError> {
    let docker_max_disk_percentage_usage_before_purge = 60; // arbitrary percentage that should make the job anytime
    let available_space = docker_path_size_info.get_available_space();
    let docker_percentage_remaining = available_space * 100 / docker_path_size_info.get_total_space();

    if docker_percentage_remaining < docker_max_disk_percentage_usage_before_purge || available_space == 0 {
        warn!(
            "Docker disk remaining ({}%) is lower than {}%, requesting cleaning (purge)",
            docker_percentage_remaining, docker_max_disk_percentage_usage_before_purge
        );

        return match docker_prune_images(&envs) {
            Err(e) => {
                error!("error while purging docker images: {:?}", e.message);
                Err(e)
            }
            _ => Ok("docker images have been purged".to_string()),
        };
    };

    Ok(format!(
        "no need to purge old docker images, only {}% ({}/{}) disk used",
        100 - docker_percentage_remaining,
        docker_path_size_info.get_available_space(),
        docker_path_size_info.get_total_space(),
    ))
}

pub fn docker_prune_images(envs: &Vec<(&str, &str)>) -> Result<(), SimpleError> {
    let all_prunes_commands = vec![
        vec!["container", "prune", "-f"],
        vec!["image", "prune", "-a", "-f"],
        vec!["builder", "prune", "-a", "-f"],
        vec!["volume", "prune", "-f"],
    ];

    for prune in all_prunes_commands {
        match cmd::utilities::exec_with_envs_and_output(
            "docker",
            prune.clone(),
            envs.clone(),
            |line| {
                let line_string = line.unwrap_or_default();
                debug!("{}", line_string.as_str());
            },
            |line| {
                let line_string = line.unwrap_or_default();
                debug!("{}", line_string.as_str());
            },
            Duration::minutes(consts::BUILD_DURATION_TIMEOUT_MIN),
        ) {
            Ok(_) => {}
            Err(e) => error!("error while puring {}. {:?}", prune[0], e.message),
        };
    }

    Ok(())
}
