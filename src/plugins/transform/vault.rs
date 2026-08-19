//! Plugin which issues vault tokens to services.

use faraday_compose_yml::v2 as dc;
use retry::{delay, retry, OperationResult};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    env,
    fmt::Debug,
    fs,
    io::{self, Read},
    path::PathBuf,
    result,
    time::{Duration, SystemTime},
};
use thiserror::Error;
use vaultrs::{
    api::token::requests::CreateTokenRequest, client::VaultClientSettingsBuilder,
    error::ClientError,
};

use crate::errors::*;
use crate::plugins;
use crate::plugins::{Operation, PluginGenerate, PluginNew, PluginTransform};
use crate::pod::Pod;
use crate::project::Project;
use crate::serde_helpers::{dump_yaml, load_yaml, seconds_since_epoch};
use crate::util::err;
use crate::Target;

/// How many seconds should our vault token TTL be if the user specifies nothing
/// at all? Defaults to 30 days.
const DEFAULT_TTL: u64 = 30 * 24 * 60 * 60;

/// How should our applications authenticate themselves with vault?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum AuthType {
    /// Issue time-limited VAULT_TOKEN values to each service, setting
    /// appropriate policies on each token.
    #[serde(rename = "token")]
    Token,
}

/// The policies associated with a specific pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceConfig {
    /// Set this to `true` to prevent default policies from being applied to
    /// this pod.
    #[serde(default)]
    no_default_policies: bool,

    /// Policies to apply to this service.
    #[serde(default)]
    policies: Vec<dc::RawOr<String>>,
}

/// Policies to apply to each service in a pod.
type PodConfig = BTreeMap<String, ServiceConfig>;

/// Per-target configuation.
#[derive(Clone, Debug, Default, Eq, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    /// Extra environment variables to inject into each service.
    #[serde(default)]
    extra_environment: BTreeMap<String, dc::RawOr<String>>,

    /// How long should tokens be valid for?
    ///
    /// We support `default_ttl` as an alias for backwards compatibility with
    /// 3.x and earlier.
    #[serde(default)]
    default_ttl: Option<u64>,

    /// Default policies to apply to every service.
    #[serde(default)]
    default_policies: Option<Vec<dc::RawOr<String>>>,
}

impl TargetConfig {
    /// Combine `self` with `other`, giving preferences to values in `other`.
    /// This is used to implement defaulting.
    fn extended_with(&self, other: &TargetConfig) -> TargetConfig {
        let mut extra_environment = self.extra_environment.clone();
        extra_environment.extend(other.extra_environment.clone());
        TargetConfig {
            extra_environment,
            default_ttl: other.default_ttl.or(self.default_ttl),
            default_policies: other
                .default_policies
                .clone()
                .or_else(|| self.default_policies.clone()),
        }
    }
}

#[test]
fn target_config_extension() {
    let mut e1 = BTreeMap::new();
    e1.insert("K1".to_owned(), dc::value("V1".to_owned()));
    let c1 = TargetConfig {
        extra_environment: e1,
        default_ttl: Some(1),
        default_policies: Some(vec![dc::value("p1".to_owned())]),
    };

    let mut e2 = BTreeMap::new();
    e2.insert("K2".to_owned(), dc::value("V2".to_owned()));
    let c2 = TargetConfig {
        extra_environment: e2,
        default_ttl: Some(2),
        default_policies: Some(vec![dc::value("p2".to_owned())]),
    };

    let mut e_all = BTreeMap::new();
    e_all.insert("K1".to_owned(), dc::value("V1".to_owned()));
    e_all.insert("K2".to_owned(), dc::value("V2".to_owned()));
    assert_eq!(
        c1.extended_with(&c2),
        TargetConfig {
            extra_environment: e_all.clone(),
            default_ttl: Some(2),
            default_policies: Some(vec![dc::value("p2".to_owned())]),
        }
    );
    assert_eq!(
        c2.extended_with(&c1),
        TargetConfig {
            extra_environment: e_all,
            default_ttl: Some(1),
            default_policies: Some(vec![dc::value("p1".to_owned())]),
        }
    );
}

/// The configuration for our Vault plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Only apply this plugin in the specified targets.  If this
    /// field is omitted, we apply the plguin in all targets.
    enable_in_targets: Option<Vec<String>>,

    /// The kind of authentication to use.
    auth_type: AuthType,

    /// Allow default `TargetConfig` values to be set at the top level using
    /// `serde(flatten)`.
    #[serde(flatten)]
    default_target_config: TargetConfig,

    /// Per-target configuration.
    #[serde(default)]
    targets: BTreeMap<Target, TargetConfig>,

    /// More specific policies to apply to individual
    #[serde(default)]
    pods: BTreeMap<String, PodConfig>,
}

impl Config {
    /// Get the configuration to use for `target`.
    fn target_config_for(&self, target: &Target) -> TargetConfig {
        let config = self.targets.get(target).cloned().unwrap_or_default();
        self.default_target_config.extended_with(&config)
    }
}

#[test]
fn can_deserialize_config() {
    use std::path::Path;
    let path = Path::new("examples/vault_integration/config/vault.yml");
    let config: Config = load_yaml(&path).unwrap();
    assert_eq!(config.auth_type, AuthType::Token);
}

/// Load a vault token from `~/.vault-token`, where the command line client
/// puts it.
fn load_vault_token_from_file() -> Result<String> {
    let path = dirs::home_dir()
        .ok_or_else(|| err("You do not appear to have a home directory"))?
        .join(".vault-token");
    let f = fs::File::open(&path).map_err(|e| {
        anyhow::Error::new(e).context(Error::CouldNotReadFile(path.clone()))
    })?;
    let mut reader = io::BufReader::new(f);
    let mut result = String::new();
    reader.read_to_string(&mut result).map_err(|e| {
        anyhow::Error::new(e).context(Error::CouldNotReadFile(path.clone()))
    })?;
    Ok(result.trim().to_owned())
}

/// Find the vault token we'll use to generate new tokens.
fn find_vault_token() -> Result<String> {
    env::var("VAULT_MASTER_TOKEN")
        .or_else(|_| env::var("VAULT_TOKEN"))
        .or_else(|_| load_vault_token_from_file())
        .map_err(|e| {
            err!(
                "{}.  You probably want to log in using the vault client or set \
                 VAULT_MASTER_TOKEN",
                e
            )
        })
}

/// The "environment" in which to interpret a configuration file.  We don't
/// want to use the OS environment variables, but rather a fake environment
/// with a few carefully selected values.
#[derive(Debug)]
struct ConfigEnvironment<'a> {
    /// The context for our transformation, including the project, pod,
    /// etc.
    ctx: &'a plugins::Context<'a>,
    /// The name of the current service.
    service: &'a str,
}

impl<'a> dc::Environment for ConfigEnvironment<'a> {
    fn var(&self, key: &str) -> result::Result<String, env::VarError> {
        let result = match key {
            "PROJECT" => Ok(self.ctx.project.name()),
            "TARGET" => Ok(self.ctx.project.current_target().name()),
            "POD" => Ok(self.ctx.pod.name()),
            "SERVICE" => Ok(self.service),
            _ => Err(env::VarError::NotPresent),
        };
        result.map(|s| s.to_owned())
    }
}

/// Information about a Vault token.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct TokenInfo {
    /// The actual token.
    token: String,

    /// The policies which were assigned to this token.
    policies: BTreeSet<String>,

    /// When does this expire?
    #[serde(with = "seconds_since_epoch")]
    expires: SystemTime,
}

impl TokenInfo {
    /// We want to renew a token if less than half the desired TTL is remaining.
    fn should_renew(
        &self,
        desired_policies: &BTreeSet<String>,
        desired_ttl: Duration,
    ) -> bool {
        &self.policies != desired_policies
            || SystemTime::now() + desired_ttl / 2 >= self.expires
    }
}

/// An abstract interface to Vault's token-generation capabilities.  We use
/// this to mock vault during tests.
trait GenerateToken: Debug + Sync {
    /// Get a `VAULT_ADDR` value to use along with this token.
    fn addr(&self) -> &str;
    /// Generate a token with the specified parameters.
    fn generate_token(
        &self,
        display_name: &str,
        policies: &BTreeSet<String>,
        ttl: Duration,
    ) -> Result<TokenInfo>;
}

/// An interface to an actual vault server.
#[derive(Debug)]
struct Vault {
    /// The address of our vault server.
    addr: String,
    /// The master token that we'll use to issue new tokens.
    token: String,
}

/// A failed attempt to talk to a Vault server.
#[derive(Debug, Error)]
enum VaultRequestError {
    #[error("{0}")]
    Unreachable(String),
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    Other(String),
}

impl VaultRequestError {
    fn from_client_error(error: ClientError) -> VaultRequestError {
        match error {
            ClientError::RestClientError { source } => {
                VaultRequestError::Unreachable(source.to_string())
            }
            ClientError::APIError { code, errors } => VaultRequestError::Rejected(
                format!("vault returned {}: {}", code, errors.join(", ")),
            ),
            other => VaultRequestError::Other(other.to_string()),
        }
    }

    fn is_transient(&self) -> bool {
        matches!(self, VaultRequestError::Unreachable(_))
    }
}

impl Vault {
    fn new() -> Result<Vault> {
        let addr = env::var("VAULT_ADDR").map_err(|_| {
            err(
                "Please set the environment variable VAULT_ADDR to the URL of \
                 your vault server",
            )
        })?;
        url::Url::parse(&addr).map_err(|parse_error| {
            err!("VAULT_ADDR {:?} is not a valid URL: {}", addr, parse_error)
        })?;
        let token = find_vault_token()?;
        Ok(Vault { addr, token })
    }

    #[cfg(test)]
    fn new_for_test() -> Vault {
        Vault {
            addr: "http://example.com:8200".to_owned(),
            token: "test".to_owned(),
        }
    }

    fn client(
        &self,
    ) -> std::result::Result<vaultrs::client::VaultClient, VaultRequestError> {
        let settings = VaultClientSettingsBuilder::default()
            .address(&self.addr)
            .token(&self.token)
            .timeout(Some(Duration::from_secs(30)))
            .build()
            .map_err(|build_error| {
                VaultRequestError::Other(build_error.to_string())
            })?;
        vaultrs::client::VaultClient::new(settings)
            .map_err(VaultRequestError::from_client_error)
    }

    fn retry_vault_call<Output>(
        &self,
        mut call: impl FnMut() -> std::result::Result<Output, VaultRequestError>,
    ) -> Result<Output> {
        retry(
            delay::Exponential::from_millis(200).take(4),
            || match call() {
                Ok(output) => OperationResult::Ok(output),
                Err(error) if error.is_transient() => {
                    warn!("transient vault error, retrying: {}", error);
                    OperationResult::Retry(error)
                }
                Err(error) => OperationResult::Err(error),
            },
        )
        .map_err(|retry_error| {
            anyhow::anyhow!(
                "{}: {}",
                Error::VaultError(self.addr.clone()),
                retry_error.error
            )
        })
    }
}

impl GenerateToken for Vault {
    fn addr(&self) -> &str {
        &self.addr
    }

    fn generate_token(
        &self,
        display_name: &str,
        policies: &BTreeSet<String>,
        ttl: Duration,
    ) -> Result<TokenInfo> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|runtime_error| {
                anyhow::anyhow!(
                    "{}: {}",
                    Error::VaultError(self.addr.clone()),
                    runtime_error
                )
            })?;
        let client = self.client().map_err(|client_error| {
            anyhow::anyhow!(
                "{}: {}",
                Error::VaultError(self.addr.clone()),
                client_error
            )
        })?;
        let auth = self.retry_vault_call(|| {
            runtime
                .block_on(vaultrs::token::new(
                    &client,
                    Some(
                        CreateTokenRequest::builder()
                            .display_name(display_name)
                            .renewable(true)
                            .ttl(format!("{}s", ttl.as_secs()))
                            .policies(policies.iter().cloned().collect::<Vec<_>>()),
                    ),
                ))
                .map_err(VaultRequestError::from_client_error)
        })?;
        let lease_duration = if auth.lease_duration == 0 {
            Duration::from_secs(DEFAULT_TTL)
        } else {
            Duration::from_secs(auth.lease_duration)
        };
        let expires = SystemTime::now() + lease_duration;
        Ok(TokenInfo {
            token: auth.client_token,
            // We use the passed-in policies, not `auth.policies`, just in case
            // Vault hands out a different list than we expected.
            policies: policies.to_owned(),
            expires,
        })
    }
}

/// Map the services in a pod to their `TokenInfo`.
type CachedPodTokens = BTreeMap<String, TokenInfo>;

/// Map the pods in an environment to their `TokenCachePod`.
type CachedTargetTokens = BTreeMap<String, CachedPodTokens>;

/// A cache of Vault tokens. This format is stored on disk between runs.
#[derive(Default, Deserialize, Serialize)]
struct CachedTokens {
    /// Cached token information, keyed by target, pod and service.
    targets: BTreeMap<String, CachedTargetTokens>,
}

impl CachedTokens {
    /// Look up an entry in our cache. An `Entry` is a Rust API that allows to
    /// check whether an item is present in a hash table, get it, and set it.
    fn entry(
        &mut self,
        target: String,
        pod: String,
        service: String,
    ) -> Entry<'_, String, TokenInfo> {
        self.targets
            .entry(target)
            .or_default()
            .entry(pod)
            .or_default()
            .entry(service)
    }
}

/// A token cache which wraps `GenerateToken`, and keeps a cache of generated
/// tokens.
struct TokenCache<'gen> {
    /// The generator we use to create new tokens when needed.
    generator: &'gen dyn GenerateToken,

    /// The path to our cache.
    cache_path: PathBuf,

    /// Our cache of known tokens, some of which may have expired.
    cached: CachedTokens,
}

impl<'gen> TokenCache<'gen> {
    /// Create a new `TokenCache` object for `project`, loading any existing
    /// tokens from disk.
    fn load_or_create(
        project: &Project,
        pod: &Pod,
        generator: &'gen dyn GenerateToken,
    ) -> Result<TokenCache<'gen>> {
        let cache_path = project
            .output_dir()
            .join("vault-cache")
            // We have to cache per-pod because our plugin is called in parallel.
            .join(format!("{}.yml", pod.name()));
        let cached = if cache_path.exists() {
            load_yaml(&cache_path)?
        } else {
            CachedTokens::default()
        };
        Ok(TokenCache {
            generator,
            cache_path,
            cached,
        })
    }

    /// Write our token cache to disk.
    fn save(&self) -> Result<()> {
        dump_yaml(&self.cache_path, &self.cached)
    }

    /// Fetch a token from our cache, or generate a new one.
    fn get<'cache>(
        &'cache mut self,
        project: &str,
        target: &str,
        pod: &str,
        service: &str,
        policies: &BTreeSet<String>,
        ttl: Duration,
    ) -> Result<&'cache TokenInfo> {
        // Helper functions used in several places below.
        let display_name = || format!("{}_{}_{}_{}", project, target, pod, service);
        let mkerr = |e: anyhow::Error| {
            e.context(format!("could not generate token for '{}'", service))
        };

        // Look up what we have in the cache and decide what to do.
        let entry =
            self.cached
                .entry(target.to_owned(), pod.to_owned(), service.to_owned());
        match entry {
            Entry::Vacant(vacancy) => {
                trace!("token cache does not contain {}", service);
                // We can't easily factor out any code using `self.generator`
                // while `entry` holds a mutable reference to `self.cached`,
                // because those two parts of object are currently "owned" by
                // different pieces of code, and Rust needs to be able to see
                // everything that's going on.
                let info = self
                    .generator
                    .generate_token(&display_name(), policies, ttl)
                    .map_err(mkerr)?;
                Ok(vacancy.insert(info))
            }
            Entry::Occupied(occupied) => {
                trace!("token cache hit for {}", service);
                let cached = occupied.into_mut();
                if cached.should_renew(policies, ttl) {
                    trace!("token cache needs new token for {}", service);
                    // We'll need a new token.
                    *cached = self
                        .generator
                        .generate_token(&display_name(), policies, ttl)
                        .map_err(mkerr)?;
                }
                Ok(cached)
            }
        }
    }
}

/// Issues `VAULT_TOKEN` values to services.
#[derive(Debug)]
pub struct Plugin {
    /// Our `config/vault.yml` YAML file, parsed and read into memory.
    /// Optional because if we're being run as a `PluginGenerate`, we won't
    /// have it (but it's guaranteed otherwise).
    config: Option<Config>,
    /// Our source of tokens.
    generator: Option<Box<dyn GenerateToken>>,
}

impl Plugin {
    /// Get the path to this plugin's config file.
    fn config_path(project: &Project) -> PathBuf {
        project.root_dir().join("config").join("vault.yml")
    }

    /// Create a new plugin, specifying an alternate source for tokens.
    fn new_with_generator<G>(project: &Project, generator: Option<G>) -> Result<Plugin>
    where
        G: GenerateToken + 'static,
    {
        let path = Self::config_path(project);
        let config = if path.exists() {
            Some(load_yaml(&path)?)
        } else {
            None
        };
        Ok(Plugin {
            config,
            generator: generator
                .map(|gen: G| -> Box<dyn GenerateToken> { Box::new(gen) }),
        })
    }
}

impl plugins::Plugin for Plugin {
    fn name(&self) -> &'static str {
        Self::plugin_name()
    }
}

impl PluginNew for Plugin {
    fn plugin_name() -> &'static str {
        "vault"
    }

    fn is_configured_for(project: &Project) -> Result<bool> {
        let path = Self::config_path(project);
        Ok(path.exists())
    }

    fn new(project: &Project) -> Result<Self> {
        // An annoying special case.  We may be called as a code generator,
        // in which case we don't want to try to create a `GenerateToken`
        // instance.
        let token_gen = if Self::is_configured_for(project)? {
            Some(Vault::new()?)
        } else {
            None
        };
        Self::new_with_generator(project, token_gen)
    }
}

impl PluginGenerate for Plugin {
    fn generator_description(&self) -> &'static str {
        "Get passwords & other secrets from a Vault server"
    }
}

impl PluginTransform for Plugin {
    fn transform(
        &self,
        _op: Operation,
        ctx: &plugins::Context<'_>,
        file: &mut dc::File,
    ) -> Result<()> {
        // Get our plugin config.
        let config = self
            .config
            .as_ref()
            .expect("config should always be present for transform");
        let generator = self
            .generator
            .as_ref()
            .expect("generator should always be present for transform");

        // Should this plugin be excluded in this target?
        let target = ctx.project.current_target();
        if !target.is_enabled_by(&config.enable_in_targets) {
            return Ok(());
        }

        // Set up our token cache.
        let mut cache =
            TokenCache::load_or_create(ctx.project, ctx.pod, generator.as_ref())?;

        // Apply to each service.
        for (name, service) in &mut file.services {
            // Set up a ConfigEnvironment that we can use to perform
            // interpolations of values like `$SERVICE` in our config file.
            let env = ConfigEnvironment { ctx, service: name };

            // Define a local helper function to interpolate
            // `RawOr<String>` values using `env`.
            let interpolated = |raw_val: &dc::RawOr<String>| -> Result<String> {
                let mut val = raw_val.to_owned();
                Ok(val.interpolate_env(&env)?.to_owned())
            };

            // The configuration for this pod, if present.
            let service_config = config
                .pods
                .get(ctx.pod.name())
                .and_then(|pod| pod.get(name));

            // Get a list of policy "patterns" that apply to this service.
            let target_config = config.target_config_for(target);
            let mut raw_policies =
                if service_config.map_or_else(|| false, |s| s.no_default_policies) {
                    vec![]
                } else {
                    target_config.default_policies.clone().unwrap_or_default()
                };
            raw_policies
                .extend(service_config.map_or_else(Vec::new, |s| s.policies.clone()));

            // If we have no raw policies, do nothing for this service.
            if raw_policies.is_empty() {
                debug!(
                    "Skipping token generation for {} because it has no policies",
                    name
                );
                continue;
            }

            // Interpolate the variables found in our policy patterns.
            let mut policies = BTreeSet::new();
            for result in raw_policies.iter().map(&interpolated) {
                // We'd like to use std::result::fold here but it's unstable.
                policies.insert(result?);
            }
            debug!(
                "Generating token for '{}' with policies {:?}",
                name, policies
            );

            // Insert our VAULT_ADDR value into the generated files.
            service
                .environment
                .insert("VAULT_ADDR".to_owned(), dc::escape(generator.addr())?);

            // Generate a VAULT_TOKEN.
            let ttl =
                Duration::from_secs(target_config.default_ttl.unwrap_or(DEFAULT_TTL));
            let token_info = cache.get(
                ctx.project.name(),
                ctx.project.current_target().name(),
                ctx.pod.name(),
                name,
                &policies,
                ttl,
            )?;
            service
                .environment
                .insert("VAULT_TOKEN".to_owned(), dc::escape(&token_info.token)?);

            // Add in any extra environment variables.
            for (var, val) in &target_config.extra_environment {
                service
                    .environment
                    .insert(var.to_owned(), dc::escape(interpolated(val)?)?);
            }
        }

        // Persist our tokens.
        cache.save()?;

        Ok(())
    }
}

// Put all of our tests and support code in a submodule because we're going to
// need a lot of test infrastructure.
#[cfg(test)]
mod test {
    use super::*;
    use std::{
        iter::FromIterator,
        sync::{Arc, RwLock},
    };

    /// A list of calls made to a `MockVault` instance.
    #[cfg(test)]
    type MockVaultCalls = Arc<RwLock<Vec<(String, BTreeSet<String>, Duration)>>>;

    /// A fake interface to vault for testing purposes.
    #[derive(Debug)]
    #[cfg(test)]
    struct MockVault {
        /// The tokens we were asked to generate.  We store these in a RwLock
        /// so that we can have "interior" mutability, because we don't want
        /// `generate_token` to be `&mut self` in the general case.
        calls: MockVaultCalls,
    }

    #[cfg(test)]
    impl MockVault {
        /// Create a new MockVault.
        fn new() -> MockVault {
            MockVault {
                calls: Arc::new(RwLock::new(vec![])),
            }
        }

        /// Return a reference to record of calls made to our vault.
        fn calls(&self) -> MockVaultCalls {
            self.calls.clone()
        }
    }

    #[cfg(test)]
    impl GenerateToken for MockVault {
        fn addr(&self) -> &str {
            "http://example.com:8200/"
        }

        fn generate_token(
            &self,
            display_name: &str,
            policies: &BTreeSet<String>,
            ttl: Duration,
        ) -> Result<TokenInfo> {
            self.calls.write().unwrap().push((
                display_name.to_owned(),
                policies.to_owned(),
                ttl,
            ));
            Ok(TokenInfo {
                token: "fake_token".to_owned(),
                policies: policies.to_owned(),
                expires: SystemTime::now() + ttl,
            })
        }
    }

    #[test]
    fn do_not_renew_token_if_policies_and_ttl_are_fine() {
        let desired_policies = BTreeSet::from_iter(vec!["a".to_owned()]);
        let token_info = TokenInfo {
            token: "placeholder".to_owned(),
            policies: desired_policies.clone(),
            expires: SystemTime::now() + Duration::from_secs(60),
        };
        assert!(!token_info.should_renew(&desired_policies, Duration::from_secs(60)));
    }

    #[test]
    fn renew_token_if_policies_do_not_match() {
        let desired_policies = BTreeSet::from_iter(vec!["a".to_owned()]);
        let token_info = TokenInfo {
            token: "placeholder".to_owned(),
            policies: BTreeSet::from_iter(vec!["b".to_owned()]),
            expires: SystemTime::now() + Duration::from_secs(60),
        };
        assert!(token_info.should_renew(&desired_policies, Duration::from_secs(60)));
    }

    #[test]
    fn renew_token_if_half_of_ttl_expired() {
        let desired_policies = BTreeSet::from_iter(vec!["a".to_owned()]);
        let token_info = TokenInfo {
            token: "placeholder".to_owned(),
            policies: desired_policies.clone(),
            expires: SystemTime::now() + Duration::from_secs(29),
        };
        assert!(token_info.should_renew(&desired_policies, Duration::from_secs(60)));
    }

    #[test]
    fn interpolates_policies() {
        let _ = env_logger::try_init();

        env::set_var("VAULT_ADDR", "http://example.com:8200/");
        env::set_var("VAULT_MASTER_TOKEN", "fake master token");

        let mut proj = Project::from_example("vault_integration").unwrap();
        proj.set_current_target_name("development").unwrap();

        let vault = MockVault::new();
        let calls = vault.calls();
        let plugin = Plugin::new_with_generator(&proj, Some(vault)).unwrap();

        // Check the frontend pod.
        let frontend = proj.pod("frontend").unwrap();
        let ctx = plugins::Context::new(&proj, frontend, "up");
        let mut file = frontend.merged_file(proj.current_target()).unwrap();
        plugin
            .transform(Operation::Output, &ctx, &mut file)
            .unwrap();
        let web = file.services.get("web").unwrap();
        let vault_addr = web.environment.get("VAULT_ADDR").expect("has VAULT_ADDR");
        assert_eq!(vault_addr.value().unwrap(), "http://example.com:8200/");
        let vault_token = web.environment.get("VAULT_TOKEN").expect("has VAULT_TOKEN");
        assert_eq!(vault_token.value().unwrap(), "fake_token");
        let vault_env = web.environment.get("VAULT_ENV").expect("has VAULT_ENV");
        assert_eq!(vault_env.value().unwrap(), "development");

        // Check the db pod to make sure no tokens are assigned.
        let db = proj.pod("db").unwrap();
        let ctx = plugins::Context::new(&proj, db, "up");
        let mut file = db.merged_file(proj.current_target()).unwrap();
        plugin
            .transform(Operation::Output, &ctx, &mut file)
            .unwrap();
        let dbs = file.services.get("db").unwrap();
        assert!(dbs.environment.get("VAULT_ADDR").is_none());
        assert!(dbs.environment.get("VAULT_TOKEN").is_none());
        assert!(dbs.environment.get("VAULT_ENV").is_none());

        // Check the calls made to vault.
        let calls = calls.read().unwrap();
        assert_eq!(calls.len(), 1);
        let (ref display_name, ref policies, ref ttl) = calls[0];
        assert_eq!(display_name, "vault_integration_development_frontend_web");
        assert_eq!(
            policies,
            &BTreeSet::from_iter(vec![
                "vault_integration-development".to_owned(),
                "vault_integration-development-frontend-web".to_owned(),
                "vault_integration-development-ssl".to_owned()
            ])
        );
        assert_eq!(ttl, &Duration::from_secs(2592000));
    }

    #[test]
    fn only_applied_in_specified_targets() {
        let _ = env_logger::try_init();

        let mut proj = Project::from_example("vault_integration").unwrap();
        proj.set_current_target_name("test").unwrap();
        let target = proj.current_target();

        let vault = MockVault::new();
        let plugin = Plugin::new_with_generator(&proj, Some(vault)).unwrap();

        let frontend = proj.pod("frontend").unwrap();
        let ctx = plugins::Context::new(&proj, frontend, "test");
        let mut file = frontend.merged_file(target).unwrap();
        plugin
            .transform(Operation::Output, &ctx, &mut file)
            .unwrap();
        let web = file.services.get("web").unwrap();
        assert_eq!(web.environment.get("VAULT_ADDR"), None);
    }

    #[test]
    fn connection_reset_is_transient() {
        assert!(
            VaultRequestError::Unreachable("Connection reset by peer".to_owned())
                .is_transient()
        );
    }

    #[test]
    fn vault_api_error_is_not_transient() {
        assert!(!VaultRequestError::Rejected("permission denied".to_owned())
            .is_transient());
    }

    #[test]
    fn retries_transient_vault_errors() {
        let mut attempts = 0;
        assert_eq!(
            Vault::new_for_test()
                .retry_vault_call(|| {
                    attempts += 1;
                    if attempts < 3 {
                        Err(VaultRequestError::Unreachable(
                            "Connection reset by peer".to_owned(),
                        ))
                    } else {
                        Ok(42)
                    }
                })
                .unwrap(),
            42
        );
        assert_eq!(attempts, 3);
    }

    #[test]
    fn does_not_retry_vault_api_errors() {
        let mut attempts = 0;
        assert!(Vault::new_for_test()
            .retry_vault_call(|| -> std::result::Result<i32, VaultRequestError> {
                attempts += 1;
                Err(VaultRequestError::Rejected("permission denied".to_owned()))
            })
            .is_err());
        assert_eq!(attempts, 1);
    }
}
