//! Bounded OpenVPN TCP confusion stream framing encoder and chunked decoder.
//!
//! Invariants:
//! - Standard BE16-length frames have payload sizes in `0..=MAX_PAYLOAD` (`65533` bytes).
//! - Confusion wire frames prepend a BE16 outer length (`payload_len + 2`) followed by
//!   two reserved bytes (`0x00, 0x00`) and the raw payload bytes.
//! - Both [`StreamDecoder`] (idiomatic safe port) and [`WorkspaceDecoder`] (pre-allocated
//!   zero-allocation arena) reject oversized or truncated frames fail-closed.

/// Maximum payload bytes inside a single standard BE16-length frame.
pub const MAX_PAYLOAD: usize = 65_533;

/// Maximum wire frame bytes including the 2-byte length header and 2 reserved bytes.
pub const MAX_WIRE_FRAME: usize = 65_537;

/// Maximum bytes accepted in a single [`StreamDecoder::feed`] call.
pub const MAX_FEED_INPUT: usize = MAX_WIRE_FRAME;

/// Maximum decoded output bytes produced by a single [`StreamDecoder::feed`] call.
pub const MAX_FEED_OUTPUT: usize = 2 * MAX_WIRE_FRAME;

/// Error returned when a standard or confusion wire frame violates protocol bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Frame buffer is shorter than 2 bytes or exceeds [`MAX_PAYLOAD`] + 2.
    InvalidLength,
    /// Embedded BE16 length header does not match buffer size or protocol limits.
    HeaderMismatch,
    /// Decoded output would exceed [`MAX_FEED_OUTPUT`].
    OutputOverflow,
}

/// Reads a big-endian 16-bit length from the first two bytes of `bytes`.
///
/// # Examples
/// ```
/// use szu_securelink_rs::confusion::read_be16;
/// assert_eq!(read_be16(&[0x01, 0x04]), 260);
/// ```
#[inline]
pub fn read_be16(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 8) | (bytes[1] as usize)
}

/// Appends a big-endian 16-bit integer `length` to `output`.
#[inline]
pub fn append_be16(output: &mut Vec<u8>, length: usize) {
    output.push((length >> 8) as u8);
    output.push((length & 0xff) as u8);
}

/// Encodes a single standard BE16-length OpenVPN frame into a confusion wire frame.
///
/// # Errors
/// Returns [`CodecError`] if `input` is shorter than 2 bytes, exceeds `MAX_PAYLOAD + 2`,
/// or its leading BE16 length does not equal `input.len() - 2`.
///
/// # Examples
/// ```
/// use szu_securelink_rs::confusion::encode_standard_frame;
/// let wire = encode_standard_frame(&[0x00, 0x03, b's', b'z', b'u']).unwrap();
/// assert_eq!(wire, vec![0x00, 0x05, 0x00, 0x00, b's', b'z', b'u']);
/// ```
pub fn encode_standard_frame(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut output = Vec::with_capacity(input.len() + 2);
    encode_standard_frame_into(input, &mut output)?;
    Ok(output)
}

/// Zero-allocation variant of [`encode_standard_frame`] that writes into a reusable `output` buffer.
///
/// # Errors
/// Returns [`CodecError`] on malformed length headers.
#[inline]
pub fn encode_standard_frame_into(input: &[u8], output: &mut Vec<u8>) -> Result<(), CodecError> {
    if input.len() < 2 || input.len() > MAX_PAYLOAD + 2 {
        return Err(CodecError::InvalidLength);
    }
    let length = read_be16(input);
    if length != input.len() - 2 || length > MAX_PAYLOAD {
        return Err(CodecError::HeaderMismatch);
    }
    output.clear();
    output.reserve(input.len() + 2);
    append_be16(output, length + 2);
    output.push(0);
    output.push(0);
    output.extend_from_slice(&input[2..]);
    Ok(())
}

/// Streaming confusion frame decoder that reassembles arbitrary TCP chunks into standard frames.
///
/// # Examples
/// ```
/// use szu_securelink_rs::confusion::{encode_standard_frame, StreamDecoder};
/// let wire = encode_standard_frame(&[0x00, 0x02, 0xaa, 0xbb]).unwrap();
/// let mut decoder = StreamDecoder::new();
/// assert!(decoder.feed(&wire[..3]).unwrap().is_empty());
/// assert_eq!(decoder.feed(&wire[3..]).unwrap(), vec![0x00, 0x02, 0xaa, 0xbb]);
/// ```
#[derive(Debug, Default, Clone)]
pub struct StreamDecoder {
    pending: Vec<u8>,
    expected: usize,
}

impl StreamDecoder {
    /// Creates a new empty [`StreamDecoder`] with pre-allocated frame capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Vec::with_capacity(256),
            expected: 0,
        }
    }

    /// Feeds `input` bytes into the stream decoder and returns any completed standard frames.
    ///
    /// # Errors
    /// Clears internal state and returns [`CodecError`] if `input` exceeds [`MAX_FEED_INPUT`]
    /// or contains a confusion frame with outer length `< 2`.
    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        let mut output = Vec::new();
        self.feed_into(input, &mut output)?;
        Ok(output)
    }

    /// Zero-allocation streaming decode into a caller-supplied `output` buffer.
    ///
    /// # Errors
    /// Clears internal state and returns [`CodecError`] on malformed frames.
    #[inline]
    pub fn feed_into(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<(), CodecError> {
        output.clear();
        if input.len() > MAX_FEED_INPUT {
            self.reset();
            return Err(CodecError::InvalidLength);
        }
        let mut position = 0;
        while position < input.len() {
            let target = if self.expected == 0 { 2 } else { self.expected };
            let needed = target - self.pending.len();
            let available = input.len() - position;
            let amount = needed.min(available);
            self.pending
                .extend_from_slice(&input[position..position + amount]);
            position += amount;

            if self.expected == 0 && self.pending.len() == 2 {
                let length = read_be16(&self.pending);
                if length < 2 {
                    self.reset();
                    return Err(CodecError::HeaderMismatch);
                }
                self.expected = length + 2;
            }
            if self.expected != 0 && self.pending.len() == self.expected {
                let standard_size = self.expected - 2;
                if standard_size > MAX_FEED_OUTPUT.saturating_sub(output.len()) {
                    self.reset();
                    return Err(CodecError::OutputOverflow);
                }
                append_be16(output, self.expected - 4);
                output.extend_from_slice(&self.pending[4..]);
                self.reset();
            }
        }
        Ok(())
    }

    /// Resets the decoder state, discarding any partial frame bytes while retaining capacity.
    #[inline]
    pub fn reset(&mut self) {
        self.pending.clear();
        self.expected = 0;
    }

    /// Returns the number of buffered partial frame bytes awaiting completion.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }
}
