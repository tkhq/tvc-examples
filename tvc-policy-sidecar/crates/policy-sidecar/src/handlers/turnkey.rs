use crate::state::AppState;
use axum::{Json, extract::State};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TurnkeyApiPublicKeyResponse {
    public_key: String,
    curve_type: &'static str,
}

pub(crate) async fn turnkey_api_public_key(
    State(state): State<AppState>,
) -> Json<TurnkeyApiPublicKeyResponse> {
    Json(TurnkeyApiPublicKeyResponse {
        public_key: state.turnkey_api_public_key,
        curve_type: "API_KEY_CURVE_P256",
    })
}
