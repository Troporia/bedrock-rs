use crate::error::{RakNetError, TransportLayerError};
use crate::transport::TransportLayerConnection;
use crate::transport::quic::QuicListener;
use raknet_tokio::prelude::*;

pub enum TransportLayerListener {
    RakNet(RakServer),
    /// An internal, trusted hop between two of your own processes only - never used
    /// client-facing, see `transport::quic`'s module doc. Already bound/listening by construction
    /// (`QuicListener::bind` is one async call, unlike RakServer's separate
    /// new-then-start) - this variant's `start()` is a no-op.
    Quic(QuicListener),
    // TODO: NetherNet(...),
    // TODO: Tcp(...),
}

impl TransportLayerListener {
    pub async fn start(&mut self) -> Result<(), TransportLayerError> {
        match self {
            Self::RakNet(listener) => listener.start().await.map_err(RakNetError::from)?,
            Self::Quic(_) => {}
        };

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), TransportLayerError> {
        match self {
            Self::RakNet(listener) => listener.stop().await,
            // No explicit shutdown API used here yet - dropping the underlying
            // s2n_quic::Server closes it. A graceful in-flight-stream drain on stop
            // would need this to hold onto the server rather than let Drop handle it;
            // not needed for this variant's current scope.
            Self::Quic(_) => {}
        }

        Ok(())
    }

    pub async fn accept(&mut self) -> Result<TransportLayerConnection, TransportLayerError> {
        let conn = match self {
            Self::RakNet(listener) => TransportLayerConnection::RakNet(
                listener.accept().await.map_err(RakNetError::from)?,
            ),
            Self::Quic(listener) => TransportLayerConnection::Quic(listener.accept().await?),
        };

        Ok(conn)
    }
}
