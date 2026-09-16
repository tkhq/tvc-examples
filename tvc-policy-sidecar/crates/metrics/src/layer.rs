//! Tower middleware layer for recording HTTP request metrics.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::{
    extract::MatchedPath,
    http::{Request, Response},
};
use prometheus::{Encoder, HistogramOpts, HistogramVec, Registry, TextEncoder};

pin_project_lite::pin_project! {
    /// Response future that records metrics after the inner future completes.
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
        method: String,
        path: String,
        start: Instant,
        collector: MetricsCollector,
    }
}

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result = std::task::ready!(this.inner.poll(cx));

        if let Ok(ref response) = result {
            let status = response.status().as_u16().to_string();
            let duration_ms = this.start.elapsed().as_secs_f64() * 1000.0;
            this.collector
                .histogram
                .with_label_values(&[this.method.as_str(), this.path.as_str(), &status])
                .observe(duration_ms);
        }

        Poll::Ready(result)
    }
}

/// Shared metrics state holding the prometheus registry and histogram.
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    registry: Arc<Registry>,
    histogram: HistogramVec,
}

impl MetricsCollector {
    /// Encode all registered metrics as Prometheus text format.
    ///
    /// # Errors
    ///
    /// Returns an error if metric encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(buffer)
    }

    /// Returns a reference to the underlying prometheus [`Registry`].
    ///
    /// Use this to register additional custom metrics alongside the
    /// built-in request histogram.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

/// Default histogram bucket boundaries in milliseconds.
const DEFAULT_BUCKETS_MS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
];

/// Builder for configuring a [`MetricsLayer`].
pub struct MetricsLayerBuilder {
    namespace: Option<String>,
    subsystem: Option<String>,
    buckets: Option<Vec<f64>>,
}

impl MetricsLayerBuilder {
    /// Set the Prometheus namespace (prefix for metric names).
    #[must_use]
    pub fn namespace(mut self, ns: &str) -> Self {
        self.namespace = Some(ns.to_owned());
        self
    }

    /// Set the Prometheus subsystem.
    #[must_use]
    pub fn subsystem(mut self, sub: &str) -> Self {
        self.subsystem = Some(sub.to_owned());
        self
    }

    /// Set custom histogram bucket boundaries in milliseconds.
    #[must_use]
    pub fn buckets(mut self, buckets: Vec<f64>) -> Self {
        self.buckets = Some(buckets);
        self
    }

    /// Build the [`MetricsLayer`].
    ///
    /// # Errors
    ///
    /// Returns an error if prometheus metric registration fails.
    pub fn build(self) -> Result<MetricsLayer, prometheus::Error> {
        let registry = Registry::new();
        let buckets = self.buckets.unwrap_or_else(|| DEFAULT_BUCKETS_MS.to_vec());

        let mut opts = HistogramOpts::new(
            "http_request_duration_ms",
            "HTTP request duration in milliseconds",
        )
        .buckets(buckets);

        if let Some(ns) = &self.namespace {
            opts = opts.namespace(ns.clone());
        }
        if let Some(sub) = &self.subsystem {
            opts = opts.subsystem(sub.clone());
        }

        let histogram = HistogramVec::new(opts, &["method", "path", "status"])?;

        registry.register(Box::new(histogram.clone()))?;

        Ok(MetricsLayer {
            collector: MetricsCollector {
                registry: Arc::new(registry),
                histogram,
            },
        })
    }
}

/// Tower middleware layer that records HTTP request metrics.
///
/// Wraps an inner service and records request duration, method, path,
/// and response status code as a Prometheus histogram.
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use metrics::MetricsLayer;
///
/// let layer = MetricsLayer::builder()
///     .namespace("myapp")
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MetricsLayer {
    collector: MetricsCollector,
}

impl MetricsLayer {
    /// Returns a new [`MetricsLayerBuilder`] for configuring the layer.
    #[must_use]
    pub fn builder() -> MetricsLayerBuilder {
        MetricsLayerBuilder {
            namespace: None,
            subsystem: None,
            buckets: None,
        }
    }

    /// Returns a clone of the [`MetricsCollector`] for use with the
    /// metrics handler endpoint.
    #[must_use]
    pub fn collector(&self) -> MetricsCollector {
        self.collector.clone()
    }
}

impl<S> tower::Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            collector: self.collector.clone(),
        }
    }
}

/// Tower service that records request metrics before delegating to the
/// inner service.
#[derive(Debug, Clone)]
pub struct MetricsService<S> {
    inner: S,
    collector: MetricsCollector,
}

impl<S, B, ResBody> tower::Service<Request<B>> for MetricsService<S>
where
    S: tower::Service<Request<B>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let method = request.method().to_string();
        // Use the route template, never a caller-controlled URL, to bound label cardinality.
        let path = request
            .extensions()
            .get::<MatchedPath>()
            .map_or("<unmatched>", MatchedPath::as_str)
            .to_owned();
        let start = Instant::now();

        ResponseFuture {
            inner: self.inner.call(request),
            method,
            path,
            start,
            collector: self.collector.clone(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn build_with_defaults() {
        let layer = MetricsLayer::builder().build().expect("build failed");
        let collector = layer.collector();
        let encoded = collector.encode().expect("encode failed");
        // Empty registry produces empty output
        assert!(encoded.is_empty());
    }

    #[tokio::test]
    async fn build_with_namespace() {
        let layer = MetricsLayer::builder()
            .namespace("test")
            .build()
            .expect("build failed");
        let collector = layer.collector();

        // Registry is created but no observations yet
        let encoded = collector.encode().expect("encode failed");
        assert!(encoded.is_empty());
    }

    #[tokio::test]
    async fn records_request_metrics() {
        let layer = MetricsLayer::builder()
            .namespace("test")
            .build()
            .expect("build failed");
        let collector = layer.collector();

        let app = Router::new()
            .route("/hello", get(|| async { "hi" }))
            .layer(layer);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/hello")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), 200);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(&body[..], b"hi");

        let encoded = String::from_utf8(collector.encode().expect("encode")).expect("utf8");

        assert!(
            encoded.contains("test_http_request_duration_ms"),
            "should contain namespaced metric"
        );
        assert!(
            encoded.contains("method=\"GET\""),
            "should contain method label"
        );
        assert!(
            encoded.contains("path=\"/hello\""),
            "should contain path label"
        );
        assert!(
            encoded.contains("status=\"200\""),
            "should contain status label"
        );
    }

    #[tokio::test]
    async fn aggregates_route_parameters_and_unmatched_paths() {
        let layer = MetricsLayer::builder()
            .build()
            .expect("metrics should build");
        let collector = layer.collector();
        let app = Router::new()
            .route("/users/{id}", get(|| async { "ok" }))
            .layer(layer);
        for (path, status) in [
            ("/users/alice", 200),
            ("/users/bob", 200),
            ("/missing-a", 404),
            ("/missing-b", 404),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("request should execute");
            assert_eq!(response.status(), status);
        }
        let families = collector.registry().gather();
        assert_eq!(families.len(), 1);
        let mut series: Vec<_> = families[0]
            .get_metric()
            .iter()
            .map(|metric| {
                let labels: Vec<_> = metric
                    .get_label()
                    .iter()
                    .map(|label| (label.get_name(), label.get_value()))
                    .collect();
                (labels, metric.get_histogram().get_sample_count())
            })
            .collect();
        series.sort();
        assert_eq!(
            series,
            vec![
                (
                    vec![
                        ("method", "GET"),
                        ("path", "/users/{id}"),
                        ("status", "200")
                    ],
                    2
                ),
                (
                    vec![
                        ("method", "GET"),
                        ("path", "<unmatched>"),
                        ("status", "404")
                    ],
                    2
                ),
            ]
        );
    }
}
