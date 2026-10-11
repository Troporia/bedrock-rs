use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bedrock_auth::{
    AuthData, AuthOIDC, AuthPayload, AuthType, ClientData, ConnectionRequest, encode_public_key,
};
use bedrock_protocol::V2225;
use p384::SecretKey;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rsa::RsaPrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use serde_json::json;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::login::LoginPackets;

pub(crate) fn identity_key() -> SecretKey {
    SecretKey::from_slice(&[0x33u8; 48]).unwrap()
}

pub(crate) fn client_key() -> SecretKey {
    SecretKey::from_slice(&[0x11u8; 48]).unwrap()
}

pub(crate) fn self_signed_request_bytes() -> Vec<u8> {
    let client_data = ClientData::offline("1.21.0", "127.0.0.1:19132", "Alex");
    ConnectionRequest::self_signed(&identity_key(), "Alex", &client_data)
        .unwrap()
        .to_bytes()
        .unwrap()
}

const ISSUER: &str = "https://authorization.franchise.minecraft-services.net";

fn oidc_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::new(&mut StdRng::seed_from_u64(7), 1024).expect("RSA key generates")
    })
}

pub(crate) fn trusted_oidc() -> AuthOIDC {
    let key = oidc_key();
    let jwks = serde_json::from_value(json!({ "keys": [{
        "kty": "RSA",
        "kid": "current",
        "use": "sig",
        "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(key.n().to_be_bytes()),
        "e": URL_SAFE_NO_PAD.encode(key.e().to_be_bytes()),
    }] }))
    .expect("JWKS parses");
    AuthOIDC::new(ISSUER, AuthOIDC::AUDIENCE, "https://jwks.invalid", jwks)
}

fn oidc_token(display_name: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header = json!({ "alg": "RS256", "kid": "current" });
    let claims = json!({
        "mid": "playfab", "xid": "", "xname": display_name,
        "cpk": encode_public_key(&client_key().public_key()).unwrap(),
        "iss": ISSUER, "aud": AuthOIDC::AUDIENCE,
        "nbf": now - 60, "exp": now + 3600,
    });
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(oidc_key().clone());
    let signature = URL_SAFE_NO_PAD.encode(signer.sign(message.as_bytes()).to_vec());
    format!("{message}.{signature}")
}

fn guest_login_with_token(token: String) -> V2225 {
    let client_data = ClientData::offline("1.21.0", "127.0.0.1:19132", "Guest");
    let auth = AuthData {
        auth_type: AuthType::Guest,
        auth_payload: AuthPayload::Token(token),
    };
    let request = ConnectionRequest::with_auth(auth, &client_key(), &client_data).unwrap();
    V2225::login(V2225::PROTOCOL_VERSION, request.to_bytes().unwrap())
}

pub(crate) fn verified_guest_login() -> V2225 {
    guest_login_with_token(oidc_token("Guest"))
}

pub(crate) fn forged_guest_login() -> V2225 {
    let genuine = oidc_token("Guest");
    let altered = oidc_token("Host");
    let parts = genuine.split('.').collect::<Vec<_>>();
    let altered_payload = altered.split('.').nth(1).unwrap();
    guest_login_with_token(format!("{}.{altered_payload}.{}", parts[0], parts[2]))
}

pub(crate) fn self_signed_login(display_name: &str) -> V2225 {
    let client_data = ClientData::offline("1.21.0", "127.0.0.1:19132", display_name);
    let request =
        ConnectionRequest::self_signed(&client_key(), display_name, &client_data).unwrap();
    V2225::login(V2225::PROTOCOL_VERSION, request.to_bytes().unwrap())
}
