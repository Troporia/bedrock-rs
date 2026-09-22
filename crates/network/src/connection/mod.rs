pub mod shard;

use crate::codec::{decode_packets, encode_packets};
use crate::compression::Compression;
use crate::encryption::Encryption;
use crate::error::ConnectionError;
use crate::transport::TransportLayerConnection;
use bedrock_protocol_core::Packets;
use std::marker::PhantomData;
use std::net::SocketAddr;

pub struct Connection<V: Packets> {
    /// Represents the Connection's internal transport layer, which may vary
    transport_layer: TransportLayerConnection,
    /// Represents the Connection's Compression, the compression gets initialized in the
    /// login process
    pub compression: Option<Compression>,
    /// Represents the connections encryption, the encryption gets initialized in the
    /// login process, if encryption is enabled
    pub encryption: Option<Encryption>,
    _version_marker: PhantomData<V>,
}

impl<V: Packets> Connection<V> {
    pub fn into_ver<T: Packets>(self) -> Connection<T> {
        Connection::<T> {
            transport_layer: self.transport_layer,
            compression: self.compression,
            encryption: self.encryption,
            _version_marker: PhantomData,
        }
    }

    pub fn from_transport_conn(transport_layer: TransportLayerConnection) -> Self {
        Self {
            transport_layer,
            compression: None,
            encryption: None,
            _version_marker: PhantomData,
        }
    }

    pub fn get_transport_conn(&self) -> &TransportLayerConnection {
        &self.transport_layer
    }

    pub fn get_socket_addr(&self) -> SocketAddr {
        match &self.transport_layer {
            TransportLayerConnection::RakNet(rak) => rak.get_addr(),
            TransportLayerConnection::Quic(quic) => quic.get_addr(),
        }
    }

    pub async fn send(&mut self, packets: &[V]) -> Result<(), ConnectionError> {
        let packets_stream =
            encode_packets::<V>(packets, self.compression.as_ref(), self.encryption.as_mut())?;

        self.transport_layer.send(&packets_stream).await?;

        Ok(())
    }

    pub async fn send_raw(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        self.transport_layer.send(data).await?;

        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Vec<V>, ConnectionError> {
        let packet_stream = self.transport_layer.recv().await?;

        let packets = decode_packets::<V>(
            packet_stream,
            self.compression.as_ref(),
            self.encryption.as_mut(),
        )?;

        Ok(packets)
    }

    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, ConnectionError> {
        let stream = self.transport_layer.recv().await?;

        Ok(stream)
    }

    pub async fn close(&mut self) {
        self.transport_layer.close().await;
    }

    pub async fn is_closed(&self) -> bool {
        self.transport_layer.is_closed().await
    }

    /// The RakNet protocol state (sequence/ack counters, MTU, congestion state, frame
    /// reassembly buffers) behind this connection, if it's RakNet-transported - `None`
    /// for the internal QUIC hop, which has no equivalent state to hand off. Paired with
    /// `self.encryption.as_ref().map(Encryption::export_state)` (a public field, no
    /// accessor needed), this is everything a cross-process session handoff needs to
    /// serialize - see `raknet_tokio::server::RakServer::adopt_session`, the resume side.
    pub async fn export_raknet_state(
        &self,
    ) -> Option<raknet_tokio::prelude::RakSessionState> {
        match &self.transport_layer {
            TransportLayerConnection::RakNet(session) => session.export_state().await.ok(),
            TransportLayerConnection::Quic(_) => None,
        }
    }
}
