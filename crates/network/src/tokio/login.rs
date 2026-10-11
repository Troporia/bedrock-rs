use super::connection::Connection;
use super::error::{ConnectionError, SessionError};
use super::session::Session;
use super::transport::Transport;
use crate::codec::{decode_packet, split_batch};
use crate::login::LoginAction;
use crate::login::client::{ClientIdentity, ClientLogin};
use crate::login::packets::LoginPackets;
use crate::login::server::{LoginFailure, ServerLogin, ServerLoginOptions};
use bedrock_auth::{AsyncHttpClient, HttpError, Login};

impl<V: LoginPackets, T: Transport> Connection<V, T> {
    pub async fn accept(
        self,
        options: &ServerLoginOptions,
    ) -> Result<Session<V, Box<Login>, T>, SessionError> {
        self.accept_refreshing(options, None::<&NoKeyRefresh>).await
    }

    pub async fn accept_with_refresh(
        self,
        options: &ServerLoginOptions,
        client: &impl AsyncHttpClient,
    ) -> Result<Session<V, Box<Login>, T>, SessionError> {
        self.accept_refreshing(options, Some(client)).await
    }

    async fn accept_refreshing(
        self,
        options: &ServerLoginOptions,
        client: Option<&impl AsyncHttpClient>,
    ) -> Result<Session<V, Box<Login>, T>, SessionError> {
        let mut machine = ServerLogin::new(options.clone());
        if let Some(key) = self.get_transport_conn().login_key() {
            machine.bind_transport_key(key);
        }
        let mut step = ServerStep { machine, client };
        let (connection, login, pending) = drive(self, Vec::new(), &mut step).await?;
        Ok(Session::new(connection, login, pending))
    }

    pub async fn connect(
        self,
        identity: ClientIdentity,
    ) -> Result<Session<V, (), T>, SessionError> {
        let mut machine = ClientLogin::new(identity);
        let start = machine.start();
        let (connection, (), pending) = drive(self, start, &mut machine).await?;
        Ok(Session::new(connection, (), pending))
    }
}

trait LoginStep<V, Done> {
    async fn handle(&mut self, packet: V) -> Result<Vec<LoginAction<V, Done>>, LoginFailure<V>>;
}

impl<V: LoginPackets> LoginStep<V, ()> for ClientLogin {
    async fn handle(&mut self, packet: V) -> Result<Vec<LoginAction<V>>, LoginFailure<V>> {
        Ok(ClientLogin::handle(self, packet)?)
    }
}

struct ServerStep<'a, C> {
    machine: ServerLogin,
    client: Option<&'a C>,
}

impl<V: LoginPackets, C: AsyncHttpClient> LoginStep<V, Box<Login>> for ServerStep<'_, C> {
    async fn handle(
        &mut self,
        packet: V,
    ) -> Result<Vec<LoginAction<V, Box<Login>>>, LoginFailure<V>> {
        let failure = match self.machine.handle(packet) {
            Err(failure) => failure,
            done => return done,
        };
        let Some(client) = self.client else {
            return Err(failure);
        };
        let Some(oidc) = self.machine.claim_key_refresh() else {
            return Err(failure);
        };
        if let Err(error) = oidc.refresh_async(client).await {
            tracing::warn!(%error, "refreshing the login keys failed");
        }
        self.machine.retry_login()
    }
}

struct NoKeyRefresh;

impl AsyncHttpClient for NoKeyRefresh {
    async fn get(&self, _url: &str) -> Result<Vec<u8>, HttpError> {
        Err("no http client".into())
    }
}

async fn drive<V, T, Done>(
    mut connection: Connection<V, T>,
    start: Vec<LoginAction<V, Done>>,
    step: &mut impl LoginStep<V, Done>,
) -> Result<(Connection<V, T>, Done, Vec<V>), SessionError>
where
    V: LoginPackets,
    T: Transport,
{
    match run(&mut connection, start, step).await {
        Ok((done, pending)) => Ok((connection, done, pending)),
        Err(error) => {
            connection.close().await;
            Err(error)
        }
    }
}

async fn run<V, T, Done>(
    connection: &mut Connection<V, T>,
    start: Vec<LoginAction<V, Done>>,
    step: &mut impl LoginStep<V, Done>,
) -> Result<(Done, Vec<V>), SessionError>
where
    V: LoginPackets,
    T: Transport,
{
    let mut done = None;
    let mut pending = Vec::new();

    apply_all(connection, start, &mut done).await?;

    loop {
        if let Some(done) = done.take() {
            return Ok((done, pending));
        }
        let batch = connection.recv_batch().await?;
        for frame in split_batch(&batch).map_err(ConnectionError::from)? {
            let (_, packet) = decode_packet::<V>(frame, connection.unread_bytes)
                .map_err(ConnectionError::from)?;
            if done.is_some() {
                pending.push(packet);
                continue;
            }
            match step.handle(packet).await {
                Ok(actions) => apply_all(connection, actions, &mut done).await?,
                Err(failure) => {
                    if !failure.farewell.is_empty() {
                        let _ = connection.send(&failure.farewell).await;
                    }
                    return Err(failure.error.into());
                }
            }
        }
    }
}

async fn apply_all<V: LoginPackets, T: Transport, Done>(
    connection: &mut Connection<V, T>,
    actions: Vec<LoginAction<V, Done>>,
    done: &mut Option<Done>,
) -> Result<(), SessionError> {
    for action in actions {
        match action {
            LoginAction::Send(packets) => connection.send(&packets).await?,
            LoginAction::EnableCompression(compression) => {
                connection.enable_compression(compression)
            }
            LoginAction::EnableEncryption(encryption) => connection.enable_encryption(*encryption),
            LoginAction::Complete(value) => *done = Some(value),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_packets;
    use crate::compression::Compression;
    use crate::error::LoginError;
    use crate::login::handshake::client_finish_encryption;
    use crate::login::packets::{LoginEvent, LoginStatus};
    use crate::test_helpers::{
        RotatedKeysHttp, client_key, identity_key, oidc_before_rotation, self_signed_login,
        self_signed_request_bytes, verified_online_login,
    };
    use crate::tokio::memory::{MemoryConnection, memory_connections, memory_connections_bound_to};
    use bedrock_protocol::V2225;
    use std::time::Duration;

    fn is_player_spawn(packet: V2225) -> bool {
        matches!(
            packet.into_event(),
            LoginEvent::PlayStatus(LoginStatus::PlayerSpawn)
        )
    }

    fn zlib_config(encryption: bool) -> ServerLoginOptions {
        ServerLoginOptions::default()
            .compression(Compression::Zlib {
                threshold: 1,
                compression_level: 6,
            })
            .encryption(encryption)
            .require_authentication(false)
    }

    #[::tokio::test]
    async fn client_and_server_agree_over_memory_pair() {
        let (server_conn, client_conn) = memory_connections();
        let options = zlib_config(true);

        let (server, client) = ::tokio::join!(
            server_conn.accept(&options),
            client_conn.connect(ClientIdentity::new(
                identity_key(),
                self_signed_request_bytes()
            ))
        );
        let mut server = server.unwrap();
        let mut client = client.unwrap();

        let identity = server.identity().authentication.identity();
        assert_eq!(identity.display_name, "Alex");
        assert_eq!(identity.public_key().unwrap(), identity_key().public_key());
        assert!(
            client.connection().encryption.is_some() && server.connection().encryption.is_some()
        );
        assert!(client.connection().compression.is_some());

        server
            .connection_mut()
            .send(&[V2225::play_status(LoginStatus::PlayerSpawn)])
            .await
            .unwrap();
        let down = client.connection_mut().recv().await.unwrap();
        assert!(down.into_iter().all(is_player_spawn));

        client
            .connection_mut()
            .send(&[V2225::play_status(LoginStatus::PlayerSpawn)])
            .await
            .unwrap();
        let up = server.connection_mut().recv().await.unwrap();
        assert!(up.into_iter().all(is_player_spawn));
    }

    fn rotated_keys_options() -> ServerLoginOptions {
        zlib_config(false)
            .require_authentication(true)
            .oidc(oidc_before_rotation())
    }

    async fn send_online_login(client: &mut MemoryConnection) {
        client
            .send(&[V2225::request_network_settings(V2225::PROTOCOL_VERSION)])
            .await
            .unwrap();
        client.recv().await.unwrap();
        client.enable_compression(Compression::Zlib {
            threshold: 1,
            compression_level: 6,
        });
        client.send(&[verified_online_login()]).await.unwrap();
    }

    #[::tokio::test]
    async fn a_login_signed_by_a_rotated_key_is_accepted_after_refreshing_the_keys() {
        let (server_conn, mut client_conn) = memory_connections();
        let options = rotated_keys_options();
        let http = RotatedKeysHttp::publishing("current");

        let (server, ()) = ::tokio::join!(
            server_conn.accept_with_refresh(&options, &http),
            send_online_login(&mut client_conn)
        );

        let server = server.unwrap();
        assert!(server.identity().authentication.is_authenticated());
        assert_eq!(http.requests(), ["https://jwks.invalid"]);
    }

    #[::tokio::test]
    async fn a_login_signed_by_a_rotated_key_is_refused_without_a_client() {
        let (server_conn, mut client_conn) = memory_connections();
        let options = rotated_keys_options();

        let (server, ()) = ::tokio::join!(
            server_conn.accept(&options),
            send_online_login(&mut client_conn)
        );

        assert!(matches!(
            server.map(|_| ()),
            Err(SessionError::Login(LoginError::Auth(
                bedrock_auth::AuthError::UnknownKeyId(_)
            )))
        ));
    }

    #[::tokio::test]
    async fn a_login_signed_by_an_unpublished_key_is_refused_after_one_refresh() {
        let (server_conn, mut client_conn) = memory_connections();
        let options = zlib_config(false)
            .require_authentication(true)
            .oidc(oidc_before_rotation());
        let http = RotatedKeysHttp::publishing("previous");

        let (server, ()) = ::tokio::join!(
            server_conn.accept_with_refresh(&options, &http),
            send_online_login(&mut client_conn)
        );

        assert!(matches!(
            server.map(|_| ()),
            Err(SessionError::Login(LoginError::Auth(
                bedrock_auth::AuthError::UnknownKeyId(_)
            )))
        ));
        assert_eq!(http.requests(), ["https://jwks.invalid"]);
    }

    #[::tokio::test]
    async fn a_login_from_another_key_than_the_transport_identity_is_refused() {
        let other = p384::SecretKey::from_slice(&[0x55u8; 48])
            .unwrap()
            .public_key();
        let (server_conn, client_conn) = memory_connections_bound_to(other);
        let options = zlib_config(false);

        let (server, _client) = ::tokio::join!(
            server_conn.accept(&options),
            client_conn.connect(ClientIdentity::new(
                identity_key(),
                self_signed_request_bytes()
            ))
        );

        assert!(matches!(
            server,
            Err(SessionError::Login(LoginError::TransportIdentityMismatch))
        ));
    }

    #[::tokio::test(start_paused = true)]
    async fn silent_server_times_the_client_out() {
        let (_server_conn, client_conn) = memory_connections();
        let login = client_conn.connect(ClientIdentity::new(
            identity_key(),
            self_signed_request_bytes(),
        ));
        let result = ::tokio::time::timeout(Duration::from_millis(50), login).await;
        assert!(result.is_err());
    }

    async fn play_client(client: &mut MemoryConnection, encrypted: bool, trailing: Vec<V2225>) {
        client
            .send(&[V2225::request_network_settings(V2225::PROTOCOL_VERSION)])
            .await
            .unwrap();
        let settings = client.recv().await.unwrap().remove(0);
        let LoginEvent::NetworkSettings(settings) = settings.into_event() else {
            panic!("network settings expected");
        };
        client.enable_compression(settings.compression);

        let mut batch = vec![self_signed_login("Steve")];
        if !encrypted {
            batch.extend(trailing.clone());
        }
        client.send(&batch).await.unwrap();

        if encrypted {
            let handshake = client.recv().await.unwrap().remove(0);
            let LoginEvent::ServerHandshake(token) = handshake.into_event() else {
                panic!("server handshake expected");
            };
            client.enable_encryption(client_finish_encryption(&token, &client_key()).unwrap());
            client.send(&[V2225::client_handshake()]).await.unwrap();
        }

        let status = client.recv().await.unwrap().remove(0);
        assert!(matches!(
            status.into_event(),
            LoginEvent::PlayStatus(LoginStatus::LoginSuccess)
        ));
    }

    #[::tokio::test]
    async fn accept_over_memory_pair() {
        let (server, mut client) = memory_connections();
        let options = zlib_config(true);
        let (logged_in, ()) = ::tokio::join!(
            server.accept(&options),
            play_client(&mut client, true, Vec::new())
        );
        let mut logged_in = logged_in.unwrap();
        assert_eq!(
            logged_in.identity().authentication.identity().display_name,
            "Steve"
        );
        assert!(logged_in.pending().is_empty());
        assert!(logged_in.connection().encryption.is_some());
        assert!(logged_in.connection().compression.is_some());

        let packet = V2225::play_status(LoginStatus::PlayerSpawn);
        logged_in
            .connection_mut()
            .send(std::slice::from_ref(&packet))
            .await
            .unwrap();
        logged_in
            .connection_mut()
            .send(std::slice::from_ref(&packet))
            .await
            .unwrap();
        let received = client.recv().await.unwrap();
        assert!(matches!(
            received.into_iter().next().unwrap().into_event(),
            LoginEvent::PlayStatus(LoginStatus::PlayerSpawn)
        ));
        let on_the_wire = client.recv_raw().await.unwrap();
        let plain = encode_packets::<V2225>(&[packet], None, None).unwrap();
        assert_ne!(on_the_wire, plain);
        assert_ne!(on_the_wire.len(), plain.len());
    }

    #[::tokio::test]
    async fn accept_keeps_packets_batched_after_login() {
        let (server, mut client) = memory_connections();
        let options = zlib_config(false);
        let trailing = vec![V2225::request_network_settings(1)];
        let (logged_in, ()) = ::tokio::join!(
            server.accept(&options),
            play_client(&mut client, false, trailing)
        );
        let logged_in = logged_in.unwrap();
        assert_eq!(logged_in.pending().len(), 1);
        assert!(logged_in.connection().encryption.is_none());
    }

    #[::tokio::test(start_paused = true)]
    async fn accept_times_out_on_a_silent_client() {
        let (server, _client) = memory_connections();
        let options = ServerLoginOptions::default();
        let result =
            ::tokio::time::timeout(Duration::from_millis(50), server.accept(&options)).await;
        assert!(result.is_err());
    }

    #[::tokio::test]
    async fn accept_sends_the_farewell_before_failing() {
        let (server, mut client) = memory_connections();
        let options = zlib_config(false);
        let client_side = async {
            client
                .send(&[V2225::request_network_settings(1)])
                .await
                .unwrap();
            client.recv().await.unwrap().remove(0).into_event()
        };
        let (result, event) = ::tokio::join!(server.accept(&options), client_side);
        assert!(matches!(
            result,
            Err(SessionError::Login(LoginError::ProtocolMismatch {
                client: 1,
                ..
            }))
        ));
        assert!(matches!(
            event,
            LoginEvent::PlayStatus(LoginStatus::LoginFailedClientOld)
        ));
    }

    #[::tokio::test]
    async fn accept_rejects_the_first_unexpected_packet_before_decoding_the_rest() {
        let (server, mut client) = memory_connections();
        let options = zlib_config(false);
        let mut batch =
            encode_packets::<V2225>(&[V2225::play_status(LoginStatus::LoginSuccess)], None, None)
                .unwrap();
        batch.extend([1, 0xff]);
        let client_side = client.send_batch(batch);
        let (result, sent) = ::tokio::join!(server.accept(&options), client_side);
        sent.unwrap();
        assert!(matches!(
            result,
            Err(SessionError::Login(LoginError::UnexpectedPacket { .. }))
        ));
    }
}
