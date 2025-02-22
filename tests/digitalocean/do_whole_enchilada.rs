use ::function_name::named;
use qovery_engine::cloud_provider::digitalocean::application::Region;
use qovery_engine::cloud_provider::Kind;
use qovery_engine::models::EnvironmentAction;
use test_utilities::common::{cluster_test, ClusterDomain, ClusterTestType};
use test_utilities::digitalocean::{DO_KUBERNETES_MAJOR_VERSION, DO_KUBERNETES_MINOR_VERSION};
use test_utilities::utilities::{context, engine_run_test, generate_cluster_id, generate_id, logger, FuncTestsSecrets};

#[cfg(feature = "test-do-whole-enchilada")]
#[named]
#[test]
fn create_upgrade_and_destroy_doks_cluster_with_env_in_ams_3() {
    let context = context();
    let logger = logger();
    let region = Region::Amsterdam3;
    let secrets = FuncTestsSecrets::new();
    let organization_id = generate_id();
    let cluster_id = generate_cluster_id(region.as_str());
    let cluster_domain = format!(
        "{}.{}",
        cluster_id.as_str(),
        secrets
            .DEFAULT_TEST_DOMAIN
            .as_ref()
            .expect("DEFAULT_TEST_DOMAIN is not set in secrets")
            .as_str()
    );

    let environment = test_utilities::common::working_minimal_environment(
        &context,
        organization_id.as_str(),
        cluster_domain.as_str(),
    );
    let env_action = EnvironmentAction::Environment(environment.clone());

    engine_run_test(|| {
        cluster_test(
            function_name!(),
            Kind::Do,
            context.clone(),
            logger,
            region.as_str(),
            secrets.clone(),
            ClusterTestType::Classic,
            DO_KUBERNETES_MAJOR_VERSION,
            DO_KUBERNETES_MINOR_VERSION,
            ClusterDomain::Custom(cluster_domain),
            None,
            Some(&env_action),
        )
    })
}
