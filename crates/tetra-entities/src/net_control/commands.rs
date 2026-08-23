// ---------------------------------------------------------------------------
// Command / CommandResponse — concrete enums sent through the channel
//
// The command server sends a Command; the stack processes it and returns
// a CommandResponse.  Placeholder variants are provided for now.
// ---------------------------------------------------------------------------

use bitcode::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Command received from the remote command server.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub enum ControlCommand {
    /// Command to send an SDS for local delivery
    SendSds {
        handle: u32,
        source_ssi: u32,
        dest_ssi: u32,
        dest_is_group: bool,
        len_bits: u16,
        payload: Vec<u8>,
    },

    /// Atomically replace the local CA neighbour list and D-NWRK-BROADCAST
    /// settings. It intentionally does not retune SDR hardware.
    UpdateCellAdvertisement {
        handle: u32,
        neighbour_ids: Vec<String>,
        cell_reselect_parameters: u16,
        cell_load_ca: u8,
        time_enabled: bool,
        timezone: Option<String>,
    },

    /// Placeholder command A.
    CommandA { handle: u32, parameter: u32 },
    /// Placeholder command B.
    TestCmdB {
        handle: u32,
        source_ssi: u32,
        is_group: bool,
        payload: Vec<u8>,
    },
}

/// Response sent back to the remote command server after processing a [`Command`].
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub enum ControlResponse {
    /// Response to [`Command::CommandA`].
    CommandAResponse { handle: u32, result: u32 },
    /// Response to [`Command::SendSds`].
    SendSdsResponse { handle: u32, success: bool },
    UpdateCellAdvertisementResponse {
        handle: u32,
        success: bool,
        version: u64,
        error: Option<String>,
    },
}
