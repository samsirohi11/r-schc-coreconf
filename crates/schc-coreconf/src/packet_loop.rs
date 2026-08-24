//! Small packet-device polling seam used by the synchronous endpoint loops.

use std::io;

use schc_runtime::packet::{PacketDevice, PacketDeviceError};
use thiserror::Error;

/// The result of one bounded packet-device poll.
#[derive(Debug, Eq, PartialEq)]
pub enum PacketPoll {
    /// No packet was ready.
    Idle,
    /// One complete packet was read.
    Packet(Vec<u8>),
}

/// Errors from packet-device polling and writes.
#[derive(Debug, Error)]
pub enum PacketLoopError {
    /// A packet-device operation failed.
    #[error("TUN packet-device operation failed: {0}")]
    Device(#[from] PacketDeviceError),
    /// The device consumed fewer bytes than one complete packet.
    #[error("short TUN packet write: expected {expected} bytes, wrote {actual}")]
    ShortWrite {
        /// Number of bytes supplied to the device.
        expected: usize,
        /// Number of bytes consumed by the device.
        actual: usize,
    },
}

/// Owns one packet device for one endpoint event loop.
#[derive(Debug)]
pub struct PacketEventLoop<D> {
    device: D,
}

impl<D: PacketDevice> PacketEventLoop<D> {
    /// Creates a packet event loop around its exclusive packet device.
    #[must_use]
    pub const fn new(device: D) -> Self {
        Self { device }
    }

    /// Polls once without turning the normal nonblocking idle condition into
    /// an endpoint failure.
    ///
    /// # Errors
    ///
    /// Returns an error for a real packet-device failure.
    pub fn poll(&mut self) -> Result<PacketPoll, PacketLoopError> {
        match self.device.read_packet() {
            Ok(packet) => Ok(PacketPoll::Packet(packet)),
            Err(PacketDeviceError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                Ok(PacketPoll::Idle)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Writes one complete packet and rejects a short device write.
    ///
    /// # Errors
    ///
    /// Returns an error for device I/O failures or short writes.
    pub fn write(&mut self, packet: &[u8]) -> Result<(), PacketLoopError> {
        let written = self.device.write_packet(packet)?;
        if written != packet.len() {
            return Err(PacketLoopError::ShortWrite {
                expected: packet.len(),
                actual: written,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        reads: Vec<Result<Vec<u8>, PacketDeviceError>>,
        write_len: usize,
    }

    impl PacketDevice for Fake {
        fn read_packet(&mut self) -> Result<Vec<u8>, PacketDeviceError> {
            self.reads.remove(0)
        }
        fn write_packet(&mut self, _packet: &[u8]) -> Result<usize, PacketDeviceError> {
            Ok(self.write_len)
        }
    }

    #[test]
    fn would_block_is_idle() {
        let fake = Fake {
            reads: vec![Err(io::Error::from(io::ErrorKind::WouldBlock).into())],
            write_len: 0,
        };
        assert_eq!(PacketEventLoop::new(fake).poll().unwrap(), PacketPoll::Idle);
    }

    #[test]
    fn short_write_is_reported() {
        let fake = Fake {
            reads: vec![],
            write_len: 1,
        };
        let error = PacketEventLoop::new(fake).write(&[1, 2]).unwrap_err();
        assert!(matches!(
            error,
            PacketLoopError::ShortWrite {
                expected: 2,
                actual: 1
            }
        ));
    }
}
