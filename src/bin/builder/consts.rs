pub const BUILD_DURATION_TIMEOUT_MIN: i64 = 30;

/// https://buildpacks.io/
pub const BUILDPACKS_BUILDERS: [&str; 1] = [
    "heroku/buildpacks:20",
    // removed because it does not support dynamic port binding
    //"gcr.io/buildpacks/builder:v1",
    //"paketobuildpacks/builder:base",
];
