use crate::db::Repository;
use crate::error::GatewayError;
use crate::plugins::abort::AbortPlugin;
use crate::plugins::acl::AclPlugin;
use crate::plugins::anomaly_detector::AnomalyDetectorPlugin;
use crate::plugins::auth::AuthPlugin;
use crate::plugins::basic_auth::BasicAuthPlugin;
use crate::plugins::bot_detection::BotDetectionPlugin;
use crate::plugins::buffering::BufferingPlugin;
use crate::plugins::canary::CanaryPlugin;
use crate::plugins::client_cert_header::ClientCertHeaderPlugin;
use crate::plugins::content_type::ContentTypePlugin;
use crate::plugins::correlation_id::CorrelationIdPlugin;
use crate::plugins::cors::CorsPlugin;
use crate::plugins::datadog::DatadogPlugin;
use crate::plugins::digest_auth::DigestAuthPlugin;
use crate::plugins::error_handler::ErrorHandlerPlugin;
use crate::plugins::file_log::FileLogPlugin;
use crate::plugins::forward_auth::ForwardAuthPlugin;
use crate::plugins::graphql_guard::GraphqlGuardPlugin;
use crate::plugins::grpc_web::GrpcWebPlugin;
use crate::plugins::hmac_auth::HmacAuthPlugin;
use crate::plugins::honeycomb::HoneycombPlugin;
use crate::plugins::inflight_req::InFlightReqPlugin;
use crate::plugins::ip_restriction::IpRestrictionPlugin;
use crate::plugins::jwt::JwtPlugin;
use crate::plugins::key_auth::KeyAuthPlugin;
use crate::plugins::llm_gateway::LlmGatewayPlugin;
use crate::plugins::log_filter::LogFilterPlugin;
use crate::plugins::logging::LoggingPlugin;
use crate::plugins::map_vars::MapVarsPlugin;
use crate::plugins::method_override::MethodOverridePlugin;
use crate::plugins::mocking::MockingPlugin;
use crate::plugins::oauth2_introspect::Oauth2IntrospectPlugin;
use crate::plugins::openapi_drift::OpenApiDriftPlugin;
use crate::plugins::openapi_mock::OpenApiMockPlugin;
use crate::plugins::opentelemetry::OpenTelemetryPlugin;
use crate::plugins::prometheus_per_consumer::PrometheusPerConsumerPlugin;
use crate::plugins::proxy_cache::ProxyCachePlugin;
use crate::plugins::rate_limit::RateLimitPlugin;
use crate::plugins::redirect::RedirectPlugin;
use crate::plugins::redirect_regex::RedirectRegexPlugin;
use crate::plugins::redis_rate_limit::RedisRateLimitPlugin;
use crate::plugins::request_cleaner::RequestCleanerPlugin;
use crate::plugins::request_id::RequestIdPlugin;
use crate::plugins::request_recorder::RequestRecorderPlugin;
use crate::plugins::request_size_limit::RequestSizeLimitPlugin;
use crate::plugins::request_termination::RequestTerminationPlugin;
use crate::plugins::request_transformer::RequestTransformerPlugin;
use crate::plugins::request_validator::RequestValidatorPlugin;
use crate::plugins::response_cleaner::ResponseCleanerPlugin;
use crate::plugins::response_compression::ResponseCompressionPlugin;
use crate::plugins::response_filter::ResponseFilterPlugin;
use crate::plugins::response_ratelimiting::ResponseRateLimitingPlugin;
use crate::plugins::response_rewriter::ResponseRewriterPlugin;
use crate::plugins::response_transformer::ResponseTransformerPlugin;
use crate::plugins::script_runner::ScriptRunnerPlugin;
use crate::plugins::security_headers::SecurityHeadersPlugin;
use crate::plugins::session::SessionPlugin;
use crate::plugins::shadow::ShadowPlugin;
use crate::plugins::splunk::SplunkPlugin;
use crate::plugins::statsd::StatsdPlugin;
use crate::plugins::syslog::SyslogPlugin;
use crate::plugins::template::TemplatePlugin;
use crate::plugins::wasm::WasmPlugin;
use crate::plugins::websocket_size_limit::WebsocketSizeLimitPlugin;
use crate::plugins::Plugin;
use std::sync::Arc;

/// Construct a plugin from its persisted name + config blob.
///
/// * `repo` — optional, consulted by plugins that need DB access (consumer
///   lookup, etc.). Plugins that don't need it ignore it.
/// * `ctx` — shared service handles (currently just an optional keyx
///   client). Plugins that don't need anything from the context ignore it.
/// * `tier` — the deployment's subscription tier. Plugins that gate their
///   algorithm by tier (currently `rate-limit`) consult it; the rest
///   ignore it.
pub fn build(
    name: &str,
    config: &serde_json::Value,
    repo: Option<Arc<dyn Repository>>,
    ctx: &crate::plugins::PluginContext,
    tier: algorithms::backbone::Tier,
) -> Result<Arc<dyn Plugin>, GatewayError> {
    let plugin: Arc<dyn Plugin> = match name {
        "rate-limit" => Arc::new(RateLimitPlugin::from_config(config, tier)?),
        "cors" => Arc::new(CorsPlugin::from_config(config)?),
        "logging" => Arc::new(LoggingPlugin::from_config(config)?),
        "auth" => Arc::new(AuthPlugin::from_config(config)?),
        "ip-restriction" => Arc::new(IpRestrictionPlugin::from_config(config)?),
        "request-size-limit" => Arc::new(RequestSizeLimitPlugin::from_config(config)?),
        "request-transformer" => Arc::new(RequestTransformerPlugin::from_config(config)?),
        "response-transformer" => Arc::new(ResponseTransformerPlugin::from_config(config)?),
        "bot-detection" => Arc::new(BotDetectionPlugin::from_config(config)?),
        "jwt" => Arc::new(JwtPlugin::from_config(config)?),
        "basic-auth" => Arc::new(BasicAuthPlugin::from_config(config, repo)?),
        "key-auth" => Arc::new(KeyAuthPlugin::from_config(config, repo)?),
        "proxy-cache" => Arc::new(ProxyCachePlugin::from_config(config)?),
        "request-termination" => Arc::new(RequestTerminationPlugin::from_config(config)?),
        "oauth2-introspect" => Arc::new(Oauth2IntrospectPlugin::from_config(config, repo)?),
        "hmac-auth" => Arc::new(HmacAuthPlugin::from_config(config, repo, ctx)?),
        "acl" => Arc::new(AclPlugin::from_config(config)?),
        "request-validator" => Arc::new(RequestValidatorPlugin::from_config(config, repo)?),
        "session" => Arc::new(SessionPlugin::from_config(config, repo)?),
        "statsd" => Arc::new(StatsdPlugin::from_config(config)?),
        "datadog" => Arc::new(DatadogPlugin::from_config(config)?),
        "redis-rate-limit" => Arc::new(RedisRateLimitPlugin::from_config(config)?),
        "opentelemetry" => Arc::new(OpenTelemetryPlugin::from_config(config)?),
        "syslog" => Arc::new(SyslogPlugin::from_config(config)?),
        "file-log" => Arc::new(FileLogPlugin::from_config(config)?),
        "prometheus-per-consumer" => Arc::new(PrometheusPerConsumerPlugin::from_config(config)?),
        "request-id" => Arc::new(RequestIdPlugin::from_config(config)?),
        "request-recorder" => Arc::new(RequestRecorderPlugin::from_config(config, repo)?),
        "correlation-id" => Arc::new(CorrelationIdPlugin::from_config(config)?),
        "splunk" => Arc::new(SplunkPlugin::from_config(config)?),
        "honeycomb" => Arc::new(HoneycombPlugin::from_config(config)?),
        "grpc-web" => Arc::new(GrpcWebPlugin::from_config(config)?),
        "mocking" => Arc::new(MockingPlugin::from_config(config)?),
        "response-ratelimiting" => Arc::new(ResponseRateLimitingPlugin::from_config(config)?),
        "request-cleaner" => Arc::new(RequestCleanerPlugin::from_config(config)?),
        "response-cleaner" => Arc::new(ResponseCleanerPlugin::from_config(config)?),
        "response-compression" => Arc::new(ResponseCompressionPlugin::from_config(config)?),
        "forward-auth" => Arc::new(ForwardAuthPlugin::from_config(config)?),
        "response-rewriter" => Arc::new(ResponseRewriterPlugin::from_config(config)?),
        "canary" => Arc::new(CanaryPlugin::from_config(config)?),
        "shadow" => Arc::new(ShadowPlugin::from_config(config)?),
        "websocket-size-limit" => Arc::new(WebsocketSizeLimitPlugin::from_config(config)?),
        "llm-gateway" => Arc::new(LlmGatewayPlugin::from_config(config)?),
        "graphql-guard" => Arc::new(GraphqlGuardPlugin::from_config(config)?),
        "wasm" => Arc::new(WasmPlugin::from_config(config)?),
        "openapi-drift" => Arc::new(OpenApiDriftPlugin::from_config(config)?),
        "openapi-mock" => Arc::new(OpenApiMockPlugin::from_config(config)?),
        "anomaly-detector" => Arc::new(AnomalyDetectorPlugin::from_config(config)?),
        "script-runner" => Arc::new(ScriptRunnerPlugin::from_config(config)?),
        "error-handler" => Arc::new(ErrorHandlerPlugin::from_config(config)?),
        "redirect" => Arc::new(RedirectPlugin::from_config(config)?),
        "template" => Arc::new(TemplatePlugin::from_config(config)?),
        "log-filter" => Arc::new(LogFilterPlugin::from_config(config)?),
        "abort" => Arc::new(AbortPlugin::from_config(config)?),
        "method-override" => Arc::new(MethodOverridePlugin::from_config(config)?),
        "security-headers" => Arc::new(SecurityHeadersPlugin::from_config(config)?),
        "client-cert-header" => Arc::new(ClientCertHeaderPlugin::from_config(config)?),
        "response-filter" => Arc::new(ResponseFilterPlugin::from_config(config)?),
        "map-vars" => Arc::new(MapVarsPlugin::from_config(config)?),
        "content-type" => Arc::new(ContentTypePlugin::from_config(config)?),
        "digest-auth" => Arc::new(DigestAuthPlugin::from_config(config)?),
        "inflight-req" => Arc::new(InFlightReqPlugin::from_config(config)?),
        "redirect-regex" => Arc::new(RedirectRegexPlugin::from_config(config)?),
        "buffering" => Arc::new(BufferingPlugin::from_config(config)?),
        other => {
            return Err(GatewayError::BadRequest(format!("unknown plugin: {other}")));
        }
    };
    Ok(plugin)
}
