//! QUIC transport for an internal, trusted hop between two of your own processes - not
//! used for the client-facing side (Bedrock clients only ever speak RakNet, out of
//! anyone's control). This is meant for internal infrastructure traffic, so unlike the
//! client-facing RakNet listener there's no "arbitrary internet client" trust boundary
//! to design around - only two processes you operate need to trust each other, via a
//! pre-shared secret checked at the application layer above this transport (this
//! module only carries bytes, same as the RakNet variant does - it doesn't know or
//! care what's actually flowing over it, matching `TransportLayerConnection`'s
//! existing separation of "move bytes" from "the Bedrock login protocol that happens
//! to run over them").
//!
//! Built on `quinn`, not the `s2n_quic` the original TODO comment (now filled in) named -
//! s2n-quic 1.88.0 has a real upstream bug (its own `Token` struct is missing derives its
//! own pinned `s2n-codec`/`zerocopy` dependency now requires, confirmed by trying to
//! build against it), quinn is the other major, more commonly used Rust QUIC
//! implementation and doesn't have that landmine.
//!
//! QUIC streams are a continuous byte pipe with no built-in message boundaries (unlike
//! RakNet, where one `recv()` naturally yields one reliable frame) - `send`/`recv` here
//! add their own `u32` length prefix per call so "one send() = one receivable unit"
//! holds for this variant exactly like it does for the RakNet one, which is what
//! `Connection<V>::send`/`recv` (and everything built on them) already assumes.

use crate::error::TransportLayerError;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::Arc;

/// Self-signed certificate for the internal hop, generated once at process startup -
/// there's no public CA involved (nothing external ever connects to this listener), and
/// regenerating it every restart is fine since trust here comes from the pre-shared
/// secret checked above this layer, not from certificate pinning.
pub struct QuicIdentity {
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
}

impl QuicIdentity {
    pub fn generate() -> Result<Self, Box<dyn StdError + Send + Sync>> {
        let cert = rcgen::generate_simple_self_signed(vec!["internal-quic.local".to_string()])?;
        Ok(Self {
            cert_der: cert.cert.der().clone(),
            key_der: PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        })
    }
}

/// Explicitly installs `ring` as rustls's process-wide default `CryptoProvider`, rather
/// than relying on rustls auto-selecting the single enabled provider - that only works
/// when exactly one of `ring`/`aws-lc-rs` is linked into the whole process, which this
/// crate can't guarantee on its own: another dependency elsewhere in the same binary
/// (any binary linking this crate, not just this workspace) pulling in rustls with
/// `aws-lc-rs` is enough to make both available and break auto-detection, confirmed by
/// hitting exactly this in this crate's own workspace test run. Safe to call from every
/// entry point (`bind`/`connect`) - `install_default()` only actually takes effect
/// once; every call after the first is a harmless no-op.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct QuicListener {
    endpoint: Endpoint,
}

impl QuicListener {
    pub fn bind(addr: SocketAddr, identity: QuicIdentity) -> Result<Self, TransportLayerError> {
        ensure_crypto_provider();

        let server_config =
            ServerConfig::with_single_cert(vec![identity.cert_der], identity.key_der.into())
                .map_err(quic_setup_error)?;
        let endpoint = Endpoint::server(server_config, addr).map_err(quic_setup_error)?;
        Ok(Self { endpoint })
    }

    /// Accepts the next incoming connection and its first bidirectional stream - the
    /// caller treats one stream as one player's whole session for its lifetime; a real
    /// deployment multiplexing many players per QUIC connection would `accept_bi()` in
    /// a loop per connection instead of taking just the first one, which is a
    /// straightforward follow-up once multiple concurrent streams per connection are
    /// actually needed.
    pub async fn accept(&mut self) -> Result<QuicConnection, TransportLayerError> {
        loop {
            let Some(incoming) = self.endpoint.accept().await else {
                return Err(TransportLayerError::IOError(std::io::Error::other(
                    "QUIC listener closed",
                )));
            };

            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(err) => {
                    tracing::warn!("QUIC handshake failed: {err}");
                    continue;
                }
            };

            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let addr = connection.remote_address();
                    return Ok(QuicConnection {
                        _endpoint: None,
                        _connection: connection,
                        send,
                        recv,
                        addr,
                    });
                }
                Err(err) => {
                    tracing::warn!("QUIC stream accept failed: {err}");
                    continue;
                }
            }
        }
    }
}

pub struct QuicConnection {
    // Held for the life of the connection, never read again - purely to keep them
    // alive. Dropping a quinn `Endpoint`/`Connection` tears down the streams opened
    // through it; a local variable that went out of scope when `connect()`/`accept()`
    // returned closed the connection out from under a reply the peer was about to
    // send, confirmed by this exact failure in this module's own round-trip test
    // before these fields existed. `_endpoint` is `None` for a server-accepted
    // connection - the listener's own long-lived `Endpoint` (in `QuicListener`,
    // shared across every connection it accepts) already covers that side; only the
    // client's per-connection ephemeral endpoint needs to be held here.
    _endpoint: Option<Endpoint>,
    _connection: quinn::Connection,
    send: SendStream,
    recv: RecvStream,
    addr: SocketAddr,
}

impl QuicConnection {
    /// Connects to a QUIC listener and opens one bidirectional stream - the client
    /// side of `QuicListener::accept`. Skips server certificate verification entirely:
    /// acceptable ONLY because trust for this internal hop comes from the pre-shared
    /// secret exchanged over the stream itself (see the module doc), not from
    /// certificate validation. A production deployment should replace this with
    /// pinning the peer's actual certificate (both processes are operated by the same
    /// party, so this is a known, trackable value, not an arbitrary CA chain) rather
    /// than skipping verification outright - tracked as a known gap, not silently
    /// dropped.
    pub async fn connect(addr: SocketAddr) -> Result<Self, TransportLayerError> {
        ensure_crypto_provider();

        let mut endpoint =
            Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(quic_setup_error)?;
        let client_config = insecure_client_config()
            .map_err(|err| TransportLayerError::IOError(std::io::Error::other(err)))?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(addr, "internal-quic.local")
            .map_err(quic_setup_error)?
            .await
            .map_err(quic_io_error)?;

        let (send, recv) = connection.open_bi().await.map_err(quic_io_error)?;

        Ok(Self {
            _endpoint: Some(endpoint),
            _connection: connection,
            send,
            recv,
            addr,
        })
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<(), TransportLayerError> {
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
        framed.extend_from_slice(data);

        self.send.write_all(&framed).await.map_err(quic_io_error)
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>, TransportLayerError> {
        let mut len_buf = [0u8; 4];
        self.recv
            .read_exact(&mut len_buf)
            .await
            .map_err(quic_io_error)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut data = vec![0u8; len];
        self.recv
            .read_exact(&mut data)
            .await
            .map_err(quic_io_error)?;
        Ok(data)
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn close(&mut self) {
        let _ = self.send.finish();
    }

    pub fn is_closed(&self) -> bool {
        false // liveness is observed via recv() returning an error, same as the RakNet variant
    }
}

fn insecure_client_config() -> Result<ClientConfig, Box<dyn StdError + Send + Sync>> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnyServer))
        .with_no_client_auth();

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

fn quic_setup_error(err: impl StdError + Send + Sync + 'static) -> TransportLayerError {
    TransportLayerError::IOError(std::io::Error::other(err))
}

fn quic_io_error(err: impl StdError + Send + Sync + 'static) -> TransportLayerError {
    TransportLayerError::IOError(std::io::Error::other(err))
}

/// See `QuicConnection::connect`'s doc comment - trust for this internal hop comes from
/// the pre-shared secret checked at the application layer, not from certificate
/// validation. Explicit and named, not a silent `dangerous()` call buried inline, so
/// grepping for "TrustAnyServer" finds every place this shortcut is taken.
#[derive(Debug)]
struct TrustAnyServer;

impl rustls::client::danger::ServerCertVerifier for TrustAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The actual claim this module depends on: a client can connect, and whatever
    /// gets `send()` on one side arrives via `recv()` on the other as the exact same
    /// bytes, in both directions - proving the length-prefix framing (the thing this
    /// module adds on top of quinn's raw byte-pipe streams) actually round-trips
    /// correctly, not just that the types compile.
    ///
    /// Both sides hold their `QuicConnection` open until a `oneshot` confirms the other
    /// side is done reading, rather than dropping immediately after their own last
    /// `send()` - a real connection over this transport stays open for a whole player
    /// session, so that's the realistic shape to test, and it also avoids a genuine
    /// footgun this test caught once: `send()`/`write_all` only guarantees data was
    /// queued, not that it reached the peer, so dropping the connection (and therefore
    /// the stream) right after can race the peer's `recv()` and mangle a QUIC
    /// application-close half-way through delivery.
    #[tokio::test]
    async fn round_trips_frames_in_both_directions() {
        let identity = QuicIdentity::generate().expect("cert generation");
        let mut listener =
            QuicListener::bind("127.0.0.1:0".parse().unwrap(), identity).expect("bind");
        let addr = listener.endpoint.local_addr().expect("local addr");

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept");
            let from_client = conn.recv().await.expect("recv from client");
            conn.send(b"hello from server").await.expect("send to client");
            let _ = done_rx.await; // keep the connection alive until the client is done with it
            from_client
        });

        let mut client = QuicConnection::connect(addr).await.expect("connect");
        client.send(b"hello from client").await.expect("send to server");
        let from_server = client.recv().await.expect("recv from server");
        let _ = done_tx.send(());

        let from_client = server_task.await.expect("server task");

        assert_eq!(from_client, b"hello from client");
        assert_eq!(from_server, b"hello from server");
    }

    /// A message that spans multiple QUIC datagrams/chunks must still be reassembled
    /// correctly by the length-prefix framing - not just single-chunk-sized payloads.
    #[tokio::test]
    async fn round_trips_a_large_frame() {
        let identity = QuicIdentity::generate().expect("cert generation");
        let mut listener =
            QuicListener::bind("127.0.0.1:0".parse().unwrap(), identity).expect("bind");
        let addr = listener.endpoint.local_addr().expect("local addr");

        let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 256) as u8).collect();
        let expected = payload.clone();

        let server_task = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept");
            conn.recv().await.expect("recv large frame")
        });

        let mut client = QuicConnection::connect(addr).await.expect("connect");
        client.send(&payload).await.expect("send large frame");

        let received = server_task.await.expect("server task");
        assert_eq!(received, expected);
    }
}
