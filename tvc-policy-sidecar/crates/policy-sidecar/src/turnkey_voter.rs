//! Outbound Turnkey consensus votes signed by the quorum-derived API key.

use std::{fmt, sync::Arc, time::Duration};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::{
    TurnkeyClient, TurnkeyClientError,
    generated::immutable::activity::v1::{ApproveActivityIntent, RejectActivityIntent},
};

const TURNKEY_REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// The outbound consensus decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Vote {
    Approve,
    Reject,
}

/// A vote-submission failure retaining the SDK error for retry decisions.
#[derive(Debug)]
pub(crate) struct VoteError(TurnkeyClientError);

impl VoteError {
    pub(crate) fn is_retryable(&self) -> bool {
        match &self.0 {
            TurnkeyClientError::UnexpectedHttpStatus(status, _) => {
                matches!(status, 408 | 429 | 500..=599)
            }
            TurnkeyClientError::Http(error) => !error.is_builder() && !error.is_redirect(),
            // An incomplete or malformed response leaves the submission outcome unknown.
            // Keep delivery retries available rather than silently losing the vote.
            TurnkeyClientError::MissingContentTypeHeader
            | TurnkeyClientError::HeaderToStrError(_)
            | TurnkeyClientError::HeaderFromStrError(_)
            | TurnkeyClientError::UnexpectedMimeType(_)
            | TurnkeyClientError::Decode(_, _)
            | TurnkeyClientError::MissingActivity
            | TurnkeyClientError::MissingResult
            | TurnkeyClientError::MissingInnerResult
            | TurnkeyClientError::UnexpectedInnerActivityResult(_)
            | TurnkeyClientError::ExceededRetries(_) => true,
            TurnkeyClientError::BuilderMissingApiKey
            | TurnkeyClientError::ReqwestBuilder(_)
            | TurnkeyClientError::SerdeJsonFailure(_)
            | TurnkeyClientError::UnexpectedActivityStatus(_)
            | TurnkeyClientError::ActivityFailed(_)
            | TurnkeyClientError::ActivityRequiresApproval(_)
            | TurnkeyClientError::StamperError(_) => false,
        }
    }
}

impl fmt::Display for VoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Turnkey vote failed: {}", self.0)
    }
}

impl std::error::Error for VoteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Turnkey SDK client dedicated to quorum-key-signed decisions.
#[derive(Clone)]
pub(crate) struct TurnkeyVoter {
    client: Arc<TurnkeyClient<TurnkeyP256ApiKey>>,
}

impl TurnkeyVoter {
    pub(crate) fn new(
        api_key: TurnkeyP256ApiKey,
        base_url: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let client = TurnkeyClient::builder()
            .api_key(api_key)
            .base_url(base_url.trim_end_matches('/'))
            .connect_timeout(TURNKEY_REQUEST_TIMEOUT)
            .timeout(TURNKEY_REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    pub(crate) async fn submit(
        &self,
        organization_id: &str,
        fingerprint: &str,
        timestamp_ms: u128,
        vote: Vote,
    ) -> Result<(), VoteError> {
        let result = match vote {
            Vote::Approve => {
                self.client
                    .approve_activity(
                        organization_id.to_owned(),
                        timestamp_ms,
                        ApproveActivityIntent {
                            fingerprint: fingerprint.to_owned(),
                        },
                    )
                    .await
            }
            Vote::Reject => {
                self.client
                    .reject_activity(
                        organization_id.to_owned(),
                        timestamp_ms,
                        RejectActivityIntent {
                            fingerprint: fingerprint.to_owned(),
                        },
                    )
                    .await
            }
        };
        result.map(|_| ()).map_err(VoteError)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_terminal_activity_failures_from_uncertain_outcomes() {
        for (error, retryable) in [
            (TurnkeyClientError::ActivityFailed(None), false),
            (
                TurnkeyClientError::ActivityRequiresApproval("vote-id".to_owned()),
                false,
            ),
            (
                TurnkeyClientError::UnexpectedActivityStatus("ACTIVITY_STATUS_REJECTED".to_owned()),
                false,
            ),
            (TurnkeyClientError::MissingContentTypeHeader, true),
            (TurnkeyClientError::MissingActivity, true),
            (TurnkeyClientError::ExceededRetries(5), true),
        ] {
            let error = VoteError(error);
            assert_eq!(error.is_retryable(), retryable, "{error}");
        }
    }

    #[tokio::test]
    async fn connection_failure_retains_retryable_sdk_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener has an address");
        drop(listener);
        let key = TurnkeyP256ApiKey::from_bytes([1_u8; 32], None).expect("API key should build");
        let voter =
            TurnkeyVoter::new(key, &format!("http://{address}")).expect("voter should build");
        let error = voter
            .submit("organization-id", "fingerprint", 1, Vote::Approve)
            .await
            .expect_err("closed listener should fail");
        assert!(matches!(&error.0, TurnkeyClientError::Http(cause) if cause.is_connect()));
        assert!(error.is_retryable());
    }
}
