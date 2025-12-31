//! Message codec for Stellar overlay protocol.
//!
//! Implements length-prefixed message framing for XDR-encoded messages.
//! Each message is prefixed with a 4-byte big-endian length field.

use crate::{OverlayError, Result};
use bytes::{Buf, BufMut, BytesMut};
use stellar_xdr::curr::{AuthenticatedMessage, Limits, ReadXdr, WriteXdr};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum message size (32 MB).
const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Minimum message size (at least auth message header).
const MIN_MESSAGE_SIZE: usize = 12;

/// A framed message from the network.
#[derive(Debug)]
pub struct MessageFrame {
    /// The authenticated message.
    pub message: AuthenticatedMessage,
    /// Raw bytes for debugging.
    pub raw_len: usize,
    /// Whether the message has authentication bit set (bit 31 of length).
    pub is_authenticated: bool,
}

impl MessageFrame {
    /// Create a new message frame.
    pub fn new(message: AuthenticatedMessage, raw_len: usize, is_authenticated: bool) -> Self {
        Self { message, raw_len, is_authenticated }
    }
}

/// Codec for encoding/decoding Stellar overlay messages.
///
/// Messages are length-prefixed with a 4-byte big-endian length.
#[derive(Debug, Default)]
pub struct MessageCodec {
    /// Current decode state.
    decode_state: DecodeState,
}

#[derive(Debug, Default)]
enum DecodeState {
    /// Waiting for length prefix.
    #[default]
    ReadingLength,
    /// Reading message body of given length, with authentication flag.
    ReadingBody { len: usize, is_authenticated: bool },
}

impl MessageCodec {
    /// Create a new message codec.
    pub fn new() -> Self {
        Self {
            decode_state: DecodeState::ReadingLength,
        }
    }

    /// Encode a message to bytes.
    pub fn encode_message(message: &AuthenticatedMessage) -> Result<Vec<u8>> {
        let xdr_bytes = message.to_xdr(Limits::none())?;
        let len = xdr_bytes.len() as u32;

        let mut buf = Vec::with_capacity(4 + xdr_bytes.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&xdr_bytes);

        Ok(buf)
    }

    /// Decode bytes to a message.
    pub fn decode_message(bytes: &[u8]) -> Result<AuthenticatedMessage> {
        AuthenticatedMessage::from_xdr(bytes, Limits::none())
            .map_err(|e| OverlayError::Message(format!("failed to decode XDR: {}", e)))
    }
}

impl Decoder for MessageCodec {
    type Item = MessageFrame;
    type Error = OverlayError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        loop {
            match self.decode_state {
                DecodeState::ReadingLength => {
                    if src.len() < 4 {
                        // Need more data for length
                        return Ok(None);
                    }

                    // Read length prefix
                    // In Stellar's protocol, bit 31 indicates authentication status
                    // Bit 31 set = message has valid MAC
                    // Bit 31 clear = message has zero MAC (Hello/Auth during handshake)
                    let raw_len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
                    let is_authenticated = (raw_len & 0x80000000) != 0;
                    let len = (raw_len & 0x7FFFFFFF) as usize;

                    // Validate length
                    if len < MIN_MESSAGE_SIZE {
                        return Err(OverlayError::Message(format!(
                            "message too small: {} bytes",
                            len
                        )));
                    }
                    if len > MAX_MESSAGE_SIZE {
                        return Err(OverlayError::Message(format!(
                            "message too large: {} bytes",
                            len
                        )));
                    }

                    // Advance past length prefix
                    src.advance(4);

                    // Reserve space for message body
                    src.reserve(len);

                    self.decode_state = DecodeState::ReadingBody { len, is_authenticated };
                }
                DecodeState::ReadingBody { len, is_authenticated } => {
                    if src.len() < len {
                        // Need more data for message body
                        return Ok(None);
                    }

                    // Read message body
                    let body = src.split_to(len);

                    // Decode XDR
                    let message = Self::decode_message(&body)?;

                    // Reset state
                    self.decode_state = DecodeState::ReadingLength;

                    return Ok(Some(MessageFrame::new(message, len, is_authenticated)));
                }
            }
        }
    }
}

impl Encoder<AuthenticatedMessage> for MessageCodec {
    type Error = OverlayError;

    fn encode(&mut self, message: AuthenticatedMessage, dst: &mut BytesMut) -> Result<()> {
        // Encode to XDR
        let xdr_bytes = message.to_xdr(Limits::none())?;

        // Check size
        if xdr_bytes.len() > MAX_MESSAGE_SIZE {
            return Err(OverlayError::Message(format!(
                "message too large: {} bytes",
                xdr_bytes.len()
            )));
        }

        // Write length prefix
        let len = xdr_bytes.len() as u32;
        dst.reserve(4 + xdr_bytes.len());
        dst.put_u32(len);

        // Write message body
        dst.extend_from_slice(&xdr_bytes);

        Ok(())
    }
}

/// Helper functions for message encoding.
pub mod helpers {
    use super::*;
    use stellar_xdr::curr::StellarMessage;

    /// Calculate the hash of a StellarMessage for flood tracking.
    pub fn message_hash(message: &StellarMessage) -> stellar_core_common::Hash256 {
        let bytes = message.to_xdr(Limits::none()).unwrap_or_default();
        stellar_core_common::Hash256::hash(&bytes)
    }

    /// Check if a message type should be flooded.
    pub fn is_flood_message(message: &StellarMessage) -> bool {
        matches!(
            message,
            StellarMessage::Transaction(_)
                | StellarMessage::ScpMessage(_)
                | StellarMessage::FloodAdvert(_)
                | StellarMessage::FloodDemand(_)
        )
    }

    /// Check if a message is a handshake message.
    pub fn is_handshake_message(message: &StellarMessage) -> bool {
        matches!(message, StellarMessage::Hello(_) | StellarMessage::Auth(_))
    }

    /// Get a human-readable name for a message type.
    pub fn message_type_name(message: &StellarMessage) -> &'static str {
        match message {
            StellarMessage::ErrorMsg(_) => "ERROR",
            StellarMessage::Hello(_) => "HELLO",
            StellarMessage::Auth(_) => "AUTH",
            StellarMessage::DontHave(_) => "DONT_HAVE",
            StellarMessage::Peers(_) => "PEERS",
            StellarMessage::GetTxSet(_) => "GET_TX_SET",
            StellarMessage::TxSet(_) => "TX_SET",
            StellarMessage::GeneralizedTxSet(_) => "GENERALIZED_TX_SET",
            StellarMessage::Transaction(_) => "TRANSACTION",
            StellarMessage::TimeSlicedSurveyRequest(_) => "TIME_SLICED_SURVEY_REQUEST",
            StellarMessage::TimeSlicedSurveyResponse(_) => "TIME_SLICED_SURVEY_RESPONSE",
            StellarMessage::TimeSlicedSurveyStartCollecting(_) => "TIME_SLICED_SURVEY_START_COLLECTING",
            StellarMessage::TimeSlicedSurveyStopCollecting(_) => "TIME_SLICED_SURVEY_STOP_COLLECTING",
            StellarMessage::GetScpQuorumset(_) => "GET_SCP_QUORUMSET",
            StellarMessage::ScpQuorumset(_) => "SCP_QUORUMSET",
            StellarMessage::ScpMessage(_) => "SCP_MESSAGE",
            StellarMessage::GetScpState(_) => "GET_SCP_STATE",
            StellarMessage::SendMore(_) => "SEND_MORE",
            StellarMessage::SendMoreExtended(_) => "SEND_MORE_EXTENDED",
            StellarMessage::FloodAdvert(_) => "FLOOD_ADVERT",
            StellarMessage::FloodDemand(_) => "FLOOD_DEMAND",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{AuthenticatedMessageV0, HmacSha256Mac, StellarMessage, VecM};

    fn make_test_message() -> AuthenticatedMessage {
        AuthenticatedMessage::V0(AuthenticatedMessageV0 {
            sequence: 0,
            message: StellarMessage::Peers(VecM::default()),
            mac: HmacSha256Mac { mac: [0u8; 32] },
        })
    }

    #[test]
    fn test_encode_decode() {
        let msg = make_test_message();
        let encoded = MessageCodec::encode_message(&msg).unwrap();

        // Should have 4-byte length prefix
        assert!(encoded.len() > 4);

        // Length should match
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(len, encoded.len() - 4);

        // Should decode
        let decoded = MessageCodec::decode_message(&encoded[4..]).unwrap();
        match decoded {
            AuthenticatedMessage::V0(v0) => {
                assert_eq!(v0.sequence, 0);
                assert!(matches!(v0.message, StellarMessage::Peers(_)));
            }
        }
    }

    #[test]
    fn test_codec_streaming() {
        let msg = make_test_message();
        let mut codec = MessageCodec::new();
        let mut buf = BytesMut::new();

        // Encode
        codec.encode(msg, &mut buf).unwrap();

        // Decode
        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_some());
    }

    #[test]
    fn test_codec_partial_read() {
        let msg = make_test_message();
        let encoded = MessageCodec::encode_message(&msg).unwrap();
        let mut codec = MessageCodec::new();

        // Feed partial data
        let mut buf = BytesMut::from(&encoded[..2]);
        assert!(codec.decode(&mut buf).unwrap().is_none());

        // Feed more data
        buf.extend_from_slice(&encoded[2..]);
        assert!(codec.decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn test_message_type_names() {
        assert_eq!(helpers::message_type_name(&StellarMessage::Peers(VecM::default())), "PEERS");
        assert_eq!(helpers::message_type_name(&StellarMessage::Hello(Default::default())), "HELLO");
    }
}
