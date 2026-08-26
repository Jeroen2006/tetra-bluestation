//! TMO OTAR PDUs from EN 300 392-7 annex A.2 and A.4b.
//!
//! This module intentionally models the standard-key (TEA set A) SCK and
//! GSKO transactions used by SC2.  It contains only air-interface values;
//! sealing/unsealing and key storage belong to the AIE state/key-provider
//! layer, never to a PDU codec.

use tetra_core::typed_pdu_fields::{Type3FieldGeneric, delimiters, typed};
use tetra_core::{BitBuffer, PduParseErr, expect_pdu_type};

use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;

const U_SCK_DEMAND: u8 = 0b0010;
const U_SCK_RESULT: u8 = 0b0011;
const U_CCK_DEMAND: u8 = 0b0000;
const U_CCK_RESULT: u8 = 0b0001;
const U_GCK_DEMAND: u8 = 0b0100;
const U_GCK_RESULT: u8 = 0b0101;
const U_GSKO_DEMAND: u8 = 0b1000;
const U_GSKO_RESULT: u8 = 0b1001;
const U_KEY_STATUS_RESPONSE: u8 = 0b1011;
const D_SCK_PROVIDE: u8 = 0b0010;
const D_SCK_REJECT: u8 = 0b0011;
const D_CCK_PROVIDE: u8 = 0b0000;
const D_CCK_REJECT: u8 = 0b0001;
const D_GCK_PROVIDE: u8 = 0b0100;
const D_GCK_REJECT: u8 = 0b0101;
const D_GSKO_PROVIDE: u8 = 0b1000;
const D_GSKO_REJECT: u8 = 0b1001;
const D_KEY_STATUS_DEMAND: u8 = 0b1011;

/// Optional MM fields shared by the SC2 OTAR PDUs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OtarTail {
    /// MNI for a key that applies outside the serving network.
    pub address_extension: Option<u32>,
    /// Vendor-specific Type-3 information.  It is preserved but never
    /// interpreted by the codec.
    pub proprietary: Option<Type3FieldGeneric>,
}

/// A sealed standard SCK and the metadata needed to select it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SckKeyAndIdentifier {
    pub sck_number: u8,
    pub version_number: u16,
    /// `false` for TMO, `true` for DMO.
    pub direct_mode: bool,
    /// SSCK, sealed with the KSO or EGSKO selected by the enclosing provide.
    pub sealed_key: [u8; 15],
}

/// Result for one provisioned SCK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SckNumberAndResult {
    pub sck_number: u8,
    /// A.8.61 provision-result value.
    pub provision_result: u8,
    /// Present only for `Incorrect key version number` (value 3).
    pub current_version_number: Option<u16>,
}

/// Rejection of one requested SCK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SckRejected {
    pub sck_number: u8,
    /// A.8.57b OTAR reject-reason value.
    pub reject_reason: u8,
}

/// Session key reference used for an SCK provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtarSessionKey {
    /// Individual OTAR: RSO is supplied and KSO is derived locally.
    Individual { random_seed: [u8; 10] },
    /// Group OTAR: the already held GSKO is selected by its version number.
    Group { gsko_version_number: u16 },
}

/// U-OTAR SCK DEMAND (A.2.8 / Table A.17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct USckDemand {
    pub ksg_number: u8,
    pub sck_numbers: Vec<u8>,
    pub tail: OtarTail,
}

/// U-OTAR SCK RESULT (A.2.9 / Table A.18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct USckResult {
    pub results: Vec<SckNumberAndResult>,
    pub tail: OtarTail,
}

/// D-OTAR SCK PROVIDE (A.2.7 / Table A.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSckProvide {
    pub acknowledgement_required: bool,
    /// Meaningful only if `acknowledgement_required` is true.
    pub explicit_response: bool,
    pub max_response_timer: u16,
    pub session_key: OtarSessionKey,
    pub keys: Vec<SckKeyAndIdentifier>,
    pub ksg_number: u8,
    pub retry_interval: u8,
    pub tail: OtarTail,
}

/// D-OTAR SCK REJECT (A.2.9a / Table A.19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSckReject {
    pub rejected: Vec<SckRejected>,
    pub retry_interval: u8,
    pub tail: OtarTail,
}

/// D-OTAR GSKO PROVIDE (A.2.10 / Table A.20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DGskoProvide {
    pub random_seed: [u8; 10],
    pub version_number: u16,
    /// SGSKO, sealed with the per-MS KSO.
    pub sealed_gsko: [u8; 15],
    pub cmg_gssi: u32,
    pub tail: OtarTail,
}

/// U-OTAR GSKO DEMAND (A.2.11 / Table A.21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UGskoDemand {
    pub tail: OtarTail,
}

/// U-OTAR GSKO RESULT (A.2.12 / Table A.22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UGskoResult {
    pub version_number: u16,
    pub provision_result: u8,
    pub cmg_gssi: u32,
    pub tail: OtarTail,
}

/// D-OTAR GSKO REJECT (A.2.12a / Table A.23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DGskoReject {
    pub reject_reason: u8,
    pub cmg_gssi: u32,
    pub retry_interval: u8,
    pub tail: OtarTail,
}

/// A CCK and the location areas for which it applies.  Key bytes are sealed
/// transport data; this codec never unseals or persists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CckInformation {
    pub identifier: u16,
    /// `false` denotes the current key, `true` denotes a future key.
    pub future_key_type: bool,
    pub sealed_key: [u8; 15],
    pub location_areas: CckLocationAreas,
    /// Present only for a current key when both current and future material is
    /// delivered together.
    pub future_sealed_key: Option<[u8; 15]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CckLocationAreas {
    All,
    List(Vec<u16>),
    Mask { mask: u16, selector: u16 },
    Range { lower: u16, upper: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DCckProvide {
    pub provision: Option<CckInformation>,
    pub proprietary: Option<Type3FieldGeneric>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UCckDemand {
    pub location_area: u16,
    pub proprietary: Option<Type3FieldGeneric>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UCckResult {
    pub provision_result: u8,
    pub future_provision_result: Option<u8>,
    pub proprietary: Option<Type3FieldGeneric>,
}

/// One sealed group cipher key in a GCK provide transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GckKeyAndIdentifier {
    pub gck_number: u16,
    pub version_number: u16,
    pub sealed_key: [u8; 15],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAssociation {
    GckNumber,
    Gssi(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DGckProvide {
    pub acknowledgement_required: bool,
    pub explicit_response: bool,
    pub max_response_timer: u16,
    pub session_key: OtarSessionKey,
    pub keys: Vec<GckKeyAndIdentifier>,
    pub ksg_number: u8,
    pub association: GroupAssociation,
    pub retry_interval: u8,
    pub tail: OtarTail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UGckDemand {
    pub ksg_number: u8,
    pub gck_numbers: Vec<u16>,
    pub gssis: Vec<u32>,
    pub tail: OtarTail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GckProvisionResult {
    pub gck_number: u16,
    pub version_number: u16,
    pub provision_result: u8,
    pub current_version_number: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UGckResult {
    pub results: Vec<GckProvisionResult>,
    pub tail: OtarTail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GckRejected {
    pub reject_reason: u8,
    pub association: GroupAssociation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DGckReject {
    pub rejected: Vec<GckRejected>,
    pub retry_interval: u8,
    pub tail: OtarTail,
}

/// Selection used by D-OTAR KEY STATUS DEMAND. Values follow A.27h.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatusRequest {
    Sck { number: u8 },
    SckSubset { grouping_type: u8, subset_number: u8 },
    AllScks,
    Gck { number: u16 },
    AllGcks,
    Gsko,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DKeyStatusDemand {
    pub acknowledgement_required: bool,
    pub explicit_response: bool,
    pub max_response_timer: u16,
    pub request: KeyStatusRequest,
    pub tail: OtarTail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatusResponse {
    Scks {
        grouping_type: Option<u8>,
        subset_number: Option<u8>,
        scks: Vec<SckStatus>,
    },
    Gcks(Vec<GckStatus>),
    GskoVersions(Vec<u16>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SckStatus {
    pub number: u8,
    pub version_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GckStatus {
    pub number: u16,
    pub version_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UKeyStatusResponse {
    pub response: KeyStatusResponse,
    pub tail: OtarTail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UOtar {
    CckDemand(UCckDemand),
    CckResult(UCckResult),
    SckDemand(USckDemand),
    SckResult(USckResult),
    GckDemand(UGckDemand),
    GckResult(UGckResult),
    GskoDemand(UGskoDemand),
    GskoResult(UGskoResult),
    KeyStatusResponse(UKeyStatusResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DOtar {
    CckProvide(DCckProvide),
    CckReject(DCckReject),
    SckProvide(DSckProvide),
    SckReject(DSckReject),
    GckProvide(DGckProvide),
    GckReject(DGckReject),
    GskoProvide(DGskoProvide),
    GskoReject(DGskoReject),
    KeyStatusDemand(DKeyStatusDemand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DCckReject {
    pub reject_reason: u8,
    pub retry_interval: u8,
    pub proprietary: Option<Type3FieldGeneric>,
}

impl UOtar {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        read_header(buffer, false)?;
        match buffer.read_field(4, "otar_subtype")? as u8 {
            U_CCK_DEMAND => Ok(Self::CckDemand(read_u_cck_demand(buffer)?)),
            U_CCK_RESULT => Ok(Self::CckResult(read_u_cck_result(buffer)?)),
            U_SCK_DEMAND => Ok(Self::SckDemand(read_u_sck_demand(buffer)?)),
            U_SCK_RESULT => Ok(Self::SckResult(read_u_sck_result(buffer)?)),
            U_GCK_DEMAND => Ok(Self::GckDemand(read_u_gck_demand(buffer)?)),
            U_GCK_RESULT => Ok(Self::GckResult(read_u_gck_result(buffer)?)),
            U_GSKO_DEMAND => Ok(Self::GskoDemand(UGskoDemand { tail: read_tail(buffer)? })),
            U_GSKO_RESULT => Ok(Self::GskoResult(read_u_gsko_result(buffer)?)),
            U_KEY_STATUS_RESPONSE => Ok(Self::KeyStatusResponse(read_u_key_status_response(buffer)?)),
            value => Err(PduParseErr::NotImplemented {
                field: Some(match value {
                    _ => "u_otar_subtype",
                }),
            }),
        }
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        write_header(buffer, false, self.subtype());
        match self {
            Self::CckDemand(pdu) => write_u_cck_demand(pdu, buffer),
            Self::CckResult(pdu) => write_u_cck_result(pdu, buffer),
            Self::SckDemand(pdu) => write_u_sck_demand(pdu, buffer),
            Self::SckResult(pdu) => write_u_sck_result(pdu, buffer),
            Self::GckDemand(pdu) => write_u_gck_demand(pdu, buffer),
            Self::GckResult(pdu) => write_u_gck_result(pdu, buffer),
            Self::GskoDemand(pdu) => write_tail(&pdu.tail, buffer),
            Self::GskoResult(pdu) => write_u_gsko_result(pdu, buffer),
            Self::KeyStatusResponse(pdu) => write_u_key_status_response(pdu, buffer),
        }
    }

    fn subtype(&self) -> u8 {
        match self {
            Self::CckDemand(_) => U_CCK_DEMAND,
            Self::CckResult(_) => U_CCK_RESULT,
            Self::SckDemand(_) => U_SCK_DEMAND,
            Self::SckResult(_) => U_SCK_RESULT,
            Self::GckDemand(_) => U_GCK_DEMAND,
            Self::GckResult(_) => U_GCK_RESULT,
            Self::GskoDemand(_) => U_GSKO_DEMAND,
            Self::GskoResult(_) => U_GSKO_RESULT,
            Self::KeyStatusResponse(_) => U_KEY_STATUS_RESPONSE,
        }
    }
}

impl DOtar {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        read_header(buffer, true)?;
        match buffer.read_field(4, "otar_subtype")? as u8 {
            D_CCK_PROVIDE => Ok(Self::CckProvide(read_d_cck_provide(buffer)?)),
            D_CCK_REJECT => Ok(Self::CckReject(read_d_cck_reject(buffer)?)),
            D_SCK_PROVIDE => Ok(Self::SckProvide(read_d_sck_provide(buffer)?)),
            D_SCK_REJECT => Ok(Self::SckReject(read_d_sck_reject(buffer)?)),
            D_GCK_PROVIDE => Ok(Self::GckProvide(read_d_gck_provide(buffer)?)),
            D_GCK_REJECT => Ok(Self::GckReject(read_d_gck_reject(buffer)?)),
            D_GSKO_PROVIDE => Ok(Self::GskoProvide(read_d_gsko_provide(buffer)?)),
            D_GSKO_REJECT => Ok(Self::GskoReject(read_d_gsko_reject(buffer)?)),
            D_KEY_STATUS_DEMAND => Ok(Self::KeyStatusDemand(read_d_key_status_demand(buffer)?)),
            value => Err(PduParseErr::NotImplemented {
                field: Some(match value {
                    _ => "d_otar_subtype",
                }),
            }),
        }
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        write_header(buffer, true, self.subtype());
        match self {
            Self::CckProvide(pdu) => write_d_cck_provide(pdu, buffer),
            Self::CckReject(pdu) => write_d_cck_reject(pdu, buffer),
            Self::SckProvide(pdu) => write_d_sck_provide(pdu, buffer),
            Self::SckReject(pdu) => write_d_sck_reject(pdu, buffer),
            Self::GckProvide(pdu) => write_d_gck_provide(pdu, buffer),
            Self::GckReject(pdu) => write_d_gck_reject(pdu, buffer),
            Self::GskoProvide(pdu) => write_d_gsko_provide(pdu, buffer),
            Self::GskoReject(pdu) => write_d_gsko_reject(pdu, buffer),
            Self::KeyStatusDemand(pdu) => write_d_key_status_demand(pdu, buffer),
        }
    }

    fn subtype(&self) -> u8 {
        match self {
            Self::CckProvide(_) => D_CCK_PROVIDE,
            Self::CckReject(_) => D_CCK_REJECT,
            Self::SckProvide(_) => D_SCK_PROVIDE,
            Self::SckReject(_) => D_SCK_REJECT,
            Self::GckProvide(_) => D_GCK_PROVIDE,
            Self::GckReject(_) => D_GCK_REJECT,
            Self::GskoProvide(_) => D_GSKO_PROVIDE,
            Self::GskoReject(_) => D_GSKO_REJECT,
            Self::KeyStatusDemand(_) => D_KEY_STATUS_DEMAND,
        }
    }
}

fn read_header(buffer: &mut BitBuffer, downlink: bool) -> Result<(), PduParseErr> {
    let pdu_type = buffer.read_field(4, "pdu_type")?;
    if downlink {
        expect_pdu_type!(pdu_type, MmPduTypeDl::DOtar)
    } else {
        expect_pdu_type!(pdu_type, MmPduTypeUl::UOtar)
    }
}

fn write_header(buffer: &mut BitBuffer, downlink: bool, subtype: u8) {
    buffer.write_bits(
        if downlink {
            MmPduTypeDl::DOtar.into_raw()
        } else {
            MmPduTypeUl::UOtar.into_raw()
        },
        4,
    );
    buffer.write_bits(subtype as u64, 4);
}

fn read_tail(buffer: &mut BitBuffer) -> Result<OtarTail, PduParseErr> {
    let obit = delimiters::read_obit(buffer)?;
    let address_extension = typed::parse_type2_generic(obit, buffer, 24, "address_extension")?.map(|value| value as u32);
    let proprietary = typed::parse_type3_generic(obit, buffer, 15u64)?;
    if obit && delimiters::read_mbit(buffer)? {
        return Err(PduParseErr::InvalidTrailingMbitValue);
    }
    Ok(OtarTail {
        address_extension,
        proprietary,
    })
}

fn write_tail(tail: &OtarTail, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    let obit = tail.address_extension.is_some() || tail.proprietary.is_some();
    delimiters::write_obit(buffer, obit as u8);
    if !obit {
        return Ok(());
    }
    typed::write_type2_generic(obit, buffer, tail.address_extension.map(u64::from), 24);
    typed::write_type3_generic(obit, buffer, &tail.proprietary, 15u64)?;
    delimiters::write_mbit(buffer, 0);
    Ok(())
}

fn read_array<const N: usize>(buffer: &mut BitBuffer, field: &'static str) -> Result<[u8; N], PduParseErr> {
    let mut value = [0; N];
    for byte in &mut value {
        *byte = buffer.read_field(8, field)? as u8;
    }
    Ok(value)
}

fn write_array<const N: usize>(buffer: &mut BitBuffer, value: &[u8; N]) {
    for byte in value {
        buffer.write_bits(u64::from(*byte), 8);
    }
}

fn validate(value: u8, bits: u8, field: &'static str) -> Result<(), PduParseErr> {
    if value < (1 << bits) {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field,
            value: u64::from(value),
        })
    }
}

fn validate_gssi(value: u32) -> Result<(), PduParseErr> {
    if value <= 0x00ff_ffff {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "cmg_gssi",
            value: u64::from(value),
        })
    }
}

fn read_sck_key(buffer: &mut BitBuffer) -> Result<SckKeyAndIdentifier, PduParseErr> {
    let sck_number = buffer.read_field(5, "sck_number")? as u8;
    let version_number = buffer.read_field(16, "sck_version_number")? as u16;
    let direct_mode = buffer.read_field(1, "sck_use")? != 0;
    let reserved = buffer.read_field(1, "reserved")?;
    if reserved != 0 {
        return Err(PduParseErr::InvalidValue {
            field: "reserved",
            value: reserved,
        });
    }
    Ok(SckKeyAndIdentifier {
        sck_number,
        version_number,
        direct_mode,
        sealed_key: read_array(buffer, "sealed_sck")?,
    })
}

fn write_sck_key(value: &SckKeyAndIdentifier, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.sck_number, 5, "sck_number")?;
    buffer.write_bits(u64::from(value.sck_number), 5);
    buffer.write_bits(u64::from(value.version_number), 16);
    buffer.write_bits(value.direct_mode as u64, 1);
    buffer.write_bit(0);
    write_array(buffer, &value.sealed_key);
    Ok(())
}

fn read_sck_result(buffer: &mut BitBuffer) -> Result<SckNumberAndResult, PduParseErr> {
    let sck_number = buffer.read_field(5, "sck_number")? as u8;
    let provision_result = buffer.read_field(3, "provision_result")? as u8;
    let current_version_number = (provision_result == 3)
        .then(|| buffer.read_field(16, "current_sck_version_number"))
        .transpose()?
        .map(|value| value as u16);
    Ok(SckNumberAndResult {
        sck_number,
        provision_result,
        current_version_number,
    })
}

fn write_sck_result(value: &SckNumberAndResult, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.sck_number, 5, "sck_number")?;
    validate(value.provision_result, 3, "provision_result")?;
    if (value.provision_result == 3) != value.current_version_number.is_some() {
        return Err(PduParseErr::Inconsistency {
            field: "current_sck_version_number",
            reason: "present only for incorrect key-version result",
        });
    }
    buffer.write_bits(u64::from(value.sck_number), 5);
    buffer.write_bits(u64::from(value.provision_result), 3);
    if let Some(version) = value.current_version_number {
        buffer.write_bits(u64::from(version), 16);
    }
    Ok(())
}

fn read_u_sck_demand(buffer: &mut BitBuffer) -> Result<USckDemand, PduParseErr> {
    let ksg_number = buffer.read_field(4, "ksg_number")? as u8;
    let count = buffer.read_field(3, "number_of_scks_requested")? as usize;
    let sck_numbers = (0..count)
        .map(|_| buffer.read_field(5, "sck_number").map(|value| value as u8))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(USckDemand {
        ksg_number,
        sck_numbers,
        tail: read_tail(buffer)?,
    })
}

fn write_u_sck_demand(value: &USckDemand, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.ksg_number, 4, "ksg_number")?;
    if value.sck_numbers.len() > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_scks_requested",
            value: value.sck_numbers.len() as u64,
        });
    }
    buffer.write_bits(u64::from(value.ksg_number), 4);
    buffer.write_bits(value.sck_numbers.len() as u64, 3);
    for number in &value.sck_numbers {
        validate(*number, 5, "sck_number")?;
        buffer.write_bits(u64::from(*number), 5);
    }
    write_tail(&value.tail, buffer)
}

fn read_u_sck_result(buffer: &mut BitBuffer) -> Result<USckResult, PduParseErr> {
    let count = buffer.read_field(3, "number_of_scks_provided")? as usize;
    let results = (0..count).map(|_| read_sck_result(buffer)).collect::<Result<Vec<_>, _>>()?;
    Ok(USckResult {
        results,
        tail: read_tail(buffer)?,
    })
}

fn write_u_sck_result(value: &USckResult, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.results.len() > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_scks_provided",
            value: value.results.len() as u64,
        });
    }
    buffer.write_bits(value.results.len() as u64, 3);
    for result in &value.results {
        write_sck_result(result, buffer)?;
    }
    write_tail(&value.tail, buffer)
}

fn read_d_sck_provide(buffer: &mut BitBuffer) -> Result<DSckProvide, PduParseErr> {
    let acknowledgement_required = buffer.read_field(1, "acknowledgement_flag")? != 0;
    let explicit_response = buffer.read_field(1, "explicit_response_or_reserved")? != 0;
    if !acknowledgement_required && explicit_response {
        return Err(PduParseErr::InvalidValue {
            field: "reserved",
            value: 1,
        });
    }
    let max_response_timer = buffer.read_field(16, "max_response_timer")? as u16;
    let session_key = if buffer.read_field(1, "session_key")? == 0 {
        OtarSessionKey::Individual {
            random_seed: read_array(buffer, "random_seed_for_otar")?,
        }
    } else {
        OtarSessionKey::Group {
            gsko_version_number: buffer.read_field(16, "gsko_version_number")? as u16,
        }
    };
    let count = buffer.read_field(3, "number_of_scks_provided")? as usize;
    let keys = (0..count).map(|_| read_sck_key(buffer)).collect::<Result<Vec<_>, _>>()?;
    let ksg_number = buffer.read_field(4, "ksg_number")? as u8;
    let retry_interval = buffer.read_field(3, "otar_retry_interval")? as u8;
    Ok(DSckProvide {
        acknowledgement_required,
        explicit_response,
        max_response_timer,
        session_key,
        keys,
        ksg_number,
        retry_interval,
        tail: read_tail(buffer)?,
    })
}

fn write_d_sck_provide(value: &DSckProvide, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.keys.len() > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_scks_provided",
            value: value.keys.len() as u64,
        });
    }
    validate(value.ksg_number, 4, "ksg_number")?;
    validate(value.retry_interval, 3, "otar_retry_interval")?;
    buffer.write_bits(value.acknowledgement_required as u64, 1);
    buffer.write_bits((value.acknowledgement_required && value.explicit_response) as u64, 1);
    buffer.write_bits(u64::from(value.max_response_timer), 16);
    match &value.session_key {
        OtarSessionKey::Individual { random_seed } => {
            buffer.write_bit(0);
            write_array(buffer, random_seed);
        }
        OtarSessionKey::Group { gsko_version_number } => {
            buffer.write_bit(1);
            buffer.write_bits(u64::from(*gsko_version_number), 16);
        }
    }
    buffer.write_bits(value.keys.len() as u64, 3);
    for key in &value.keys {
        write_sck_key(key, buffer)?;
    }
    buffer.write_bits(u64::from(value.ksg_number), 4);
    buffer.write_bits(u64::from(value.retry_interval), 3);
    write_tail(&value.tail, buffer)
}

fn read_d_sck_reject(buffer: &mut BitBuffer) -> Result<DSckReject, PduParseErr> {
    let count = buffer.read_field(3, "number_of_scks_rejected")? as usize;
    let rejected = (0..count)
        .map(|_| {
            Ok(SckRejected {
                sck_number: buffer.read_field(5, "sck_number")? as u8,
                reject_reason: buffer.read_field(3, "otar_reject_reason")? as u8,
            })
        })
        .collect::<Result<Vec<_>, PduParseErr>>()?;
    Ok(DSckReject {
        rejected,
        retry_interval: buffer.read_field(3, "otar_retry_interval")? as u8,
        tail: read_tail(buffer)?,
    })
}

fn write_d_sck_reject(value: &DSckReject, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.rejected.len() > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_scks_rejected",
            value: value.rejected.len() as u64,
        });
    }
    validate(value.retry_interval, 3, "otar_retry_interval")?;
    buffer.write_bits(value.rejected.len() as u64, 3);
    for rejected in &value.rejected {
        validate(rejected.sck_number, 5, "sck_number")?;
        validate(rejected.reject_reason, 3, "otar_reject_reason")?;
        buffer.write_bits(u64::from(rejected.sck_number), 5);
        buffer.write_bits(u64::from(rejected.reject_reason), 3);
    }
    buffer.write_bits(u64::from(value.retry_interval), 3);
    write_tail(&value.tail, buffer)
}

fn read_d_gsko_provide(buffer: &mut BitBuffer) -> Result<DGskoProvide, PduParseErr> {
    Ok(DGskoProvide {
        random_seed: read_array(buffer, "random_seed_for_otar")?,
        version_number: buffer.read_field(16, "gsko_version_number")? as u16,
        sealed_gsko: read_array(buffer, "sealed_gsko")?,
        cmg_gssi: buffer.read_field(24, "cmg_gssi")? as u32,
        tail: read_tail(buffer)?,
    })
}

fn write_d_gsko_provide(value: &DGskoProvide, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate_gssi(value.cmg_gssi)?;
    write_array(buffer, &value.random_seed);
    buffer.write_bits(u64::from(value.version_number), 16);
    write_array(buffer, &value.sealed_gsko);
    buffer.write_bits(u64::from(value.cmg_gssi), 24);
    write_tail(&value.tail, buffer)
}

fn read_u_gsko_result(buffer: &mut BitBuffer) -> Result<UGskoResult, PduParseErr> {
    Ok(UGskoResult {
        version_number: buffer.read_field(16, "gsko_version_number")? as u16,
        provision_result: buffer.read_field(3, "provision_result")? as u8,
        cmg_gssi: buffer.read_field(24, "cmg_gssi")? as u32,
        tail: read_tail(buffer)?,
    })
}

fn write_u_gsko_result(value: &UGskoResult, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.provision_result, 3, "provision_result")?;
    validate_gssi(value.cmg_gssi)?;
    buffer.write_bits(u64::from(value.version_number), 16);
    buffer.write_bits(u64::from(value.provision_result), 3);
    buffer.write_bits(u64::from(value.cmg_gssi), 24);
    write_tail(&value.tail, buffer)
}

fn read_d_gsko_reject(buffer: &mut BitBuffer) -> Result<DGskoReject, PduParseErr> {
    Ok(DGskoReject {
        reject_reason: buffer.read_field(3, "otar_reject_reason")? as u8,
        cmg_gssi: buffer.read_field(24, "cmg_gssi")? as u32,
        retry_interval: buffer.read_field(3, "otar_retry_interval")? as u8,
        tail: read_tail(buffer)?,
    })
}

fn write_d_gsko_reject(value: &DGskoReject, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.reject_reason, 3, "otar_reject_reason")?;
    validate_gssi(value.cmg_gssi)?;
    validate(value.retry_interval, 3, "otar_retry_interval")?;
    buffer.write_bits(u64::from(value.reject_reason), 3);
    buffer.write_bits(u64::from(value.cmg_gssi), 24);
    buffer.write_bits(u64::from(value.retry_interval), 3);
    write_tail(&value.tail, buffer)
}

fn read_cck_tail(buffer: &mut BitBuffer) -> Result<Option<Type3FieldGeneric>, PduParseErr> {
    let tail = read_tail(buffer)?;
    if tail.address_extension.is_some() {
        return Err(PduParseErr::InvalidValue {
            field: "address_extension",
            value: 1,
        });
    }
    Ok(tail.proprietary)
}

fn write_cck_tail(proprietary: &Option<Type3FieldGeneric>, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    write_tail(
        &OtarTail {
            address_extension: None,
            proprietary: proprietary.clone(),
        },
        buffer,
    )
}

fn read_d_cck_provide(buffer: &mut BitBuffer) -> Result<DCckProvide, PduParseErr> {
    let provision = (buffer.read_field(1, "cck_provision_flag")? != 0)
        .then(|| read_cck_information(buffer))
        .transpose()?;
    Ok(DCckProvide {
        provision,
        proprietary: read_cck_tail(buffer)?,
    })
}

fn write_d_cck_provide(value: &DCckProvide, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    buffer.write_bit(value.provision.is_some() as u8);
    if let Some(info) = &value.provision {
        write_cck_information(info, buffer)?;
    }
    write_cck_tail(&value.proprietary, buffer)
}

fn read_u_cck_demand(buffer: &mut BitBuffer) -> Result<UCckDemand, PduParseErr> {
    Ok(UCckDemand {
        location_area: buffer.read_field(14, "location_area")? as u16,
        proprietary: read_cck_tail(buffer)?,
    })
}

fn write_u_cck_demand(value: &UCckDemand, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.location_area >= (1 << 14) {
        return Err(PduParseErr::InvalidValue {
            field: "location_area",
            value: u64::from(value.location_area),
        });
    }
    buffer.write_bits(u64::from(value.location_area), 14);
    write_cck_tail(&value.proprietary, buffer)
}

fn read_u_cck_result(buffer: &mut BitBuffer) -> Result<UCckResult, PduParseErr> {
    let provision_result = buffer.read_field(3, "provision_result")? as u8;
    let future = buffer.read_field(1, "future_key_flag")? != 0;
    let future_provision_result = future
        .then(|| buffer.read_field(3, "future_provision_result"))
        .transpose()?
        .map(|v| v as u8);
    Ok(UCckResult {
        provision_result,
        future_provision_result,
        proprietary: read_cck_tail(buffer)?,
    })
}

fn write_u_cck_result(value: &UCckResult, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.provision_result, 3, "provision_result")?;
    if let Some(result) = value.future_provision_result {
        validate(result, 3, "future_provision_result")?;
    }
    buffer.write_bits(u64::from(value.provision_result), 3);
    buffer.write_bit(value.future_provision_result.is_some() as u8);
    if let Some(result) = value.future_provision_result {
        buffer.write_bits(u64::from(result), 3);
    }
    write_cck_tail(&value.proprietary, buffer)
}

fn read_cck_information(buffer: &mut BitBuffer) -> Result<CckInformation, PduParseErr> {
    let identifier = buffer.read_field(16, "cck_identifier")? as u16;
    let future_key_type = buffer.read_field(1, "key_type_flag")? != 0;
    let sealed_key = read_array(buffer, "sealed_cck")?;
    let location_areas = match buffer.read_field(2, "cck_location_area_type")? {
        0 => CckLocationAreas::All,
        1 => {
            let count = buffer.read_field(4, "number_of_location_areas")? as usize;
            if count == 0 {
                return Err(PduParseErr::InvalidValue {
                    field: "number_of_location_areas",
                    value: 0,
                });
            }
            CckLocationAreas::List(
                (0..count)
                    .map(|_| buffer.read_field(14, "location_area").map(|v| v as u16))
                    .collect::<Result<_, _>>()?,
            )
        }
        2 => CckLocationAreas::Mask {
            mask: buffer.read_field(14, "location_area_mask")? as u16,
            selector: buffer.read_field(14, "location_area_selector")? as u16,
        },
        3 => CckLocationAreas::Range {
            lower: buffer.read_field(14, "location_area_lower")? as u16,
            upper: buffer.read_field(14, "location_area_upper")? as u16,
        },
        _ => unreachable!(),
    };
    let future = buffer.read_field(1, "future_key_flag")? != 0;
    if future_key_type && future {
        return Err(PduParseErr::Inconsistency {
            field: "future_key_flag",
            reason: "must be zero for a future CCK",
        });
    }
    Ok(CckInformation {
        identifier,
        future_key_type,
        sealed_key,
        location_areas,
        future_sealed_key: future.then(|| read_array(buffer, "future_sealed_cck")).transpose()?,
    })
}

fn write_cck_information(value: &CckInformation, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.future_key_type && value.future_sealed_key.is_some() {
        return Err(PduParseErr::Inconsistency {
            field: "future_sealed_cck",
            reason: "a future CCK cannot carry another future key",
        });
    }
    buffer.write_bits(u64::from(value.identifier), 16);
    buffer.write_bit(value.future_key_type as u8);
    write_array(buffer, &value.sealed_key);
    match &value.location_areas {
        CckLocationAreas::All => buffer.write_bits(0, 2),
        CckLocationAreas::List(areas) => {
            if areas.is_empty() || areas.len() > 15 {
                return Err(PduParseErr::InvalidValue {
                    field: "number_of_location_areas",
                    value: areas.len() as u64,
                });
            }
            buffer.write_bits(1, 2);
            buffer.write_bits(areas.len() as u64, 4);
            for area in areas {
                if *area >= (1 << 14) {
                    return Err(PduParseErr::InvalidValue {
                        field: "location_area",
                        value: u64::from(*area),
                    });
                }
                buffer.write_bits(u64::from(*area), 14);
            }
        }
        CckLocationAreas::Mask { mask, selector } => {
            if *mask >= (1 << 14) || *selector >= (1 << 14) {
                return Err(PduParseErr::InvalidValue {
                    field: "location_area_mask_or_selector",
                    value: 0,
                });
            }
            buffer.write_bits(2, 2);
            buffer.write_bits(u64::from(*mask), 14);
            buffer.write_bits(u64::from(*selector), 14);
        }
        CckLocationAreas::Range { lower, upper } => {
            if *lower >= (1 << 14) || *upper >= (1 << 14) || lower > upper {
                return Err(PduParseErr::InvalidValue {
                    field: "location_area_range",
                    value: 0,
                });
            }
            buffer.write_bits(3, 2);
            buffer.write_bits(u64::from(*lower), 14);
            buffer.write_bits(u64::from(*upper), 14);
        }
    }
    buffer.write_bit(value.future_sealed_key.is_some() as u8);
    if let Some(key) = &value.future_sealed_key {
        write_array(buffer, key);
    }
    Ok(())
}

fn read_d_cck_reject(buffer: &mut BitBuffer) -> Result<DCckReject, PduParseErr> {
    Ok(DCckReject {
        reject_reason: buffer.read_field(3, "otar_reject_reason")? as u8,
        retry_interval: buffer.read_field(3, "otar_retry_interval")? as u8,
        proprietary: read_cck_tail(buffer)?,
    })
}

fn write_d_cck_reject(value: &DCckReject, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.reject_reason, 3, "otar_reject_reason")?;
    validate(value.retry_interval, 3, "otar_retry_interval")?;
    buffer.write_bits(u64::from(value.reject_reason), 3);
    buffer.write_bits(u64::from(value.retry_interval), 3);
    write_cck_tail(&value.proprietary, buffer)
}

fn read_d_gck_provide(buffer: &mut BitBuffer) -> Result<DGckProvide, PduParseErr> {
    let acknowledgement_required = buffer.read_field(1, "acknowledgement_flag")? != 0;
    let explicit_response = buffer.read_field(1, "explicit_response_or_reserved")? != 0;
    if !acknowledgement_required && explicit_response {
        return Err(PduParseErr::InvalidValue {
            field: "reserved",
            value: 1,
        });
    }
    let max_response_timer = buffer.read_field(16, "max_response_timer")? as u16;
    let session_key = read_session_key(buffer)?;
    let count = buffer.read_field(3, "number_of_gcks_provided")? as usize;
    let keys = (0..count).map(|_| read_gck_key(buffer)).collect::<Result<_, _>>()?;
    let ksg_number = buffer.read_field(4, "ksg_number")? as u8;
    let association = read_group_association(buffer)?;
    let retry_interval = buffer.read_field(3, "otar_retry_interval")? as u8;
    Ok(DGckProvide {
        acknowledgement_required,
        explicit_response,
        max_response_timer,
        session_key,
        keys,
        ksg_number,
        association,
        retry_interval,
        tail: read_tail(buffer)?,
    })
}

fn write_d_gck_provide(value: &DGckProvide, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.keys.len() > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_gcks_provided",
            value: value.keys.len() as u64,
        });
    }
    validate(value.ksg_number, 4, "ksg_number")?;
    validate(value.retry_interval, 3, "otar_retry_interval")?;
    buffer.write_bit(value.acknowledgement_required as u8);
    buffer.write_bit((value.acknowledgement_required && value.explicit_response) as u8);
    buffer.write_bits(u64::from(value.max_response_timer), 16);
    write_session_key(&value.session_key, buffer);
    buffer.write_bits(value.keys.len() as u64, 3);
    for key in &value.keys {
        write_gck_key(key, buffer);
    }
    buffer.write_bits(u64::from(value.ksg_number), 4);
    write_group_association(&value.association, buffer)?;
    buffer.write_bits(u64::from(value.retry_interval), 3);
    write_tail(&value.tail, buffer)
}

fn read_u_gck_demand(buffer: &mut BitBuffer) -> Result<UGckDemand, PduParseErr> {
    let ksg_number = buffer.read_field(4, "ksg_number")? as u8;
    let by_number = buffer.read_field(3, "number_of_gcks_requested_by_gckn")? as usize;
    let gck_numbers = (0..by_number)
        .map(|_| buffer.read_field(16, "gck_number").map(|v| v as u16))
        .collect::<Result<Vec<u16>, _>>()?;
    let by_gssi = buffer.read_field(3, "number_of_gcks_requested_by_gssi")? as usize;
    let gssis = (0..by_gssi)
        .map(|_| buffer.read_field(24, "gssi").map(|v| v as u32))
        .collect::<Result<Vec<u32>, _>>()?;
    validate_gck_request(&gck_numbers, &gssis)?;
    Ok(UGckDemand {
        ksg_number,
        gck_numbers,
        gssis,
        tail: read_tail(buffer)?,
    })
}

fn write_u_gck_demand(value: &UGckDemand, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    validate(value.ksg_number, 4, "ksg_number")?;
    validate_gck_request(&value.gck_numbers, &value.gssis)?;
    buffer.write_bits(u64::from(value.ksg_number), 4);
    buffer.write_bits(value.gck_numbers.len() as u64, 3);
    for n in &value.gck_numbers {
        buffer.write_bits(u64::from(*n), 16);
    }
    buffer.write_bits(value.gssis.len() as u64, 3);
    for gssi in &value.gssis {
        validate_gssi(*gssi)?;
        buffer.write_bits(u64::from(*gssi), 24);
    }
    write_tail(&value.tail, buffer)
}

fn read_u_gck_result(buffer: &mut BitBuffer) -> Result<UGckResult, PduParseErr> {
    let count = buffer.read_field(3, "number_of_gcks_provided")? as usize;
    let results = (0..count)
        .map(|_| {
            let gck_number = buffer.read_field(16, "gck_number")? as u16;
            let version_number = buffer.read_field(16, "gck_version_number")? as u16;
            let provision_result = buffer.read_field(3, "provision_result")? as u8;
            let current_version_number = (provision_result == 3)
                .then(|| buffer.read_field(16, "current_gck_version_number"))
                .transpose()?
                .map(|v| v as u16);
            Ok(GckProvisionResult {
                gck_number,
                version_number,
                provision_result,
                current_version_number,
            })
        })
        .collect::<Result<_, PduParseErr>>()?;
    Ok(UGckResult {
        results,
        tail: read_tail(buffer)?,
    })
}

fn write_u_gck_result(value: &UGckResult, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.results.len() > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_gcks_provided",
            value: value.results.len() as u64,
        });
    }
    buffer.write_bits(value.results.len() as u64, 3);
    for result in &value.results {
        validate(result.provision_result, 3, "provision_result")?;
        if (result.provision_result == 3) != result.current_version_number.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "current_gck_version_number",
                reason: "present only for incorrect key-version result",
            });
        }
        buffer.write_bits(u64::from(result.gck_number), 16);
        buffer.write_bits(u64::from(result.version_number), 16);
        buffer.write_bits(u64::from(result.provision_result), 3);
        if let Some(version) = result.current_version_number {
            buffer.write_bits(u64::from(version), 16);
        }
    }
    write_tail(&value.tail, buffer)
}

fn read_d_gck_reject(buffer: &mut BitBuffer) -> Result<DGckReject, PduParseErr> {
    let count = buffer.read_field(3, "number_of_gcks_rejected")? as usize;
    if count == 0 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_gcks_rejected",
            value: 0,
        });
    }
    let rejected = (0..count)
        .map(|_| {
            Ok(GckRejected {
                reject_reason: buffer.read_field(3, "otar_reject_reason")? as u8,
                association: read_group_association(buffer)?,
            })
        })
        .collect::<Result<_, PduParseErr>>()?;
    Ok(DGckReject {
        rejected,
        retry_interval: buffer.read_field(3, "otar_retry_interval")? as u8,
        tail: read_tail(buffer)?,
    })
}

fn write_d_gck_reject(value: &DGckReject, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.rejected.is_empty() || value.rejected.len() > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_gcks_rejected",
            value: value.rejected.len() as u64,
        });
    }
    validate(value.retry_interval, 3, "otar_retry_interval")?;
    buffer.write_bits(value.rejected.len() as u64, 3);
    for rejected in &value.rejected {
        validate(rejected.reject_reason, 3, "otar_reject_reason")?;
        buffer.write_bits(u64::from(rejected.reject_reason), 3);
        write_group_association(&rejected.association, buffer)?;
    }
    buffer.write_bits(u64::from(value.retry_interval), 3);
    write_tail(&value.tail, buffer)
}

fn read_session_key(buffer: &mut BitBuffer) -> Result<OtarSessionKey, PduParseErr> {
    if buffer.read_field(1, "session_key")? == 0 {
        Ok(OtarSessionKey::Individual {
            random_seed: read_array(buffer, "random_seed_for_otar")?,
        })
    } else {
        Ok(OtarSessionKey::Group {
            gsko_version_number: buffer.read_field(16, "gsko_version_number")? as u16,
        })
    }
}
fn write_session_key(value: &OtarSessionKey, buffer: &mut BitBuffer) {
    match value {
        OtarSessionKey::Individual { random_seed } => {
            buffer.write_bit(0);
            write_array(buffer, random_seed);
        }
        OtarSessionKey::Group { gsko_version_number } => {
            buffer.write_bit(1);
            buffer.write_bits(u64::from(*gsko_version_number), 16);
        }
    }
}
fn read_gck_key(buffer: &mut BitBuffer) -> Result<GckKeyAndIdentifier, PduParseErr> {
    Ok(GckKeyAndIdentifier {
        gck_number: buffer.read_field(16, "gck_number")? as u16,
        version_number: buffer.read_field(16, "gck_version_number")? as u16,
        sealed_key: read_array(buffer, "sealed_gck")?,
    })
}
fn write_gck_key(value: &GckKeyAndIdentifier, buffer: &mut BitBuffer) {
    buffer.write_bits(u64::from(value.gck_number), 16);
    buffer.write_bits(u64::from(value.version_number), 16);
    write_array(buffer, &value.sealed_key);
}
fn read_group_association(buffer: &mut BitBuffer) -> Result<GroupAssociation, PduParseErr> {
    if buffer.read_field(1, "group_association")? == 0 {
        Ok(GroupAssociation::GckNumber)
    } else {
        Ok(GroupAssociation::Gssi(buffer.read_field(24, "gssi")? as u32))
    }
}
fn write_group_association(value: &GroupAssociation, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    match value {
        GroupAssociation::GckNumber => buffer.write_bit(0),
        GroupAssociation::Gssi(gssi) => {
            validate_gssi(*gssi)?;
            buffer.write_bit(1);
            buffer.write_bits(u64::from(*gssi), 24);
        }
    }
    Ok(())
}
fn validate_gck_request(numbers: &[u16], gssis: &[u32]) -> Result<(), PduParseErr> {
    let count = numbers.len() + gssis.len();
    if count == 0 || count > 7 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_gcks_requested",
            value: count as u64,
        });
    }
    Ok(())
}

fn read_d_key_status_demand(buffer: &mut BitBuffer) -> Result<DKeyStatusDemand, PduParseErr> {
    let acknowledgement_required = buffer.read_field(1, "acknowledgement_flag")? != 0;
    let explicit_response = buffer.read_field(1, "explicit_response")? != 0;
    if !acknowledgement_required && explicit_response {
        return Err(PduParseErr::InvalidValue {
            field: "explicit_response",
            value: 1,
        });
    }
    let max_response_timer = buffer.read_field(16, "max_response_timer")? as u16;
    let request = match buffer.read_field(3, "key_status_type")? as u8 {
        0 => KeyStatusRequest::Sck {
            number: buffer.read_field(5, "sck_number")? as u8,
        },
        1 => KeyStatusRequest::SckSubset {
            grouping_type: buffer.read_field(4, "sck_subset_grouping_type")? as u8,
            subset_number: buffer.read_field(5, "sck_subset_number")? as u8,
        },
        2 => KeyStatusRequest::AllScks,
        3 => KeyStatusRequest::Gck {
            number: buffer.read_field(16, "gck_number")? as u16,
        },
        4 => KeyStatusRequest::AllGcks,
        5 => KeyStatusRequest::Gsko,
        value => {
            return Err(PduParseErr::InvalidValue {
                field: "key_status_type",
                value: u64::from(value),
            });
        }
    };
    Ok(DKeyStatusDemand {
        acknowledgement_required,
        explicit_response,
        max_response_timer,
        request,
        tail: read_tail(buffer)?,
    })
}

fn write_d_key_status_demand(value: &DKeyStatusDemand, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if !value.acknowledgement_required && value.explicit_response {
        return Err(PduParseErr::Inconsistency {
            field: "explicit_response",
            reason: "valid only if acknowledgement is required",
        });
    }
    buffer.write_bit(value.acknowledgement_required as u8);
    buffer.write_bit(value.explicit_response as u8);
    buffer.write_bits(u64::from(value.max_response_timer), 16);
    match value.request {
        KeyStatusRequest::Sck { number } => {
            validate(number, 5, "sck_number")?;
            buffer.write_bits(0, 3);
            buffer.write_bits(u64::from(number), 5);
        }
        KeyStatusRequest::SckSubset {
            grouping_type,
            subset_number,
        } => {
            validate(grouping_type, 4, "sck_subset_grouping_type")?;
            validate(subset_number, 5, "sck_subset_number")?;
            buffer.write_bits(1, 3);
            buffer.write_bits(u64::from(grouping_type), 4);
            buffer.write_bits(u64::from(subset_number), 5);
        }
        KeyStatusRequest::AllScks => buffer.write_bits(2, 3),
        KeyStatusRequest::Gck { number } => {
            buffer.write_bits(3, 3);
            buffer.write_bits(u64::from(number), 16);
        }
        KeyStatusRequest::AllGcks => buffer.write_bits(4, 3),
        KeyStatusRequest::Gsko => buffer.write_bits(5, 3),
    }
    write_tail(&value.tail, buffer)
}

fn read_u_key_status_response(buffer: &mut BitBuffer) -> Result<UKeyStatusResponse, PduParseErr> {
    let response = match buffer.read_field(3, "key_status_type")? as u8 {
        0 | 2 => {
            let count = buffer.read_field(6, "number_of_sck_status")? as usize;
            let scks = (0..count)
                .map(|_| {
                    Ok(SckStatus {
                        number: buffer.read_field(5, "sck_number")? as u8,
                        version_number: buffer.read_field(16, "sck_version_number")? as u16,
                    })
                })
                .collect::<Result<_, PduParseErr>>()?;
            KeyStatusResponse::Scks {
                grouping_type: None,
                subset_number: None,
                scks,
            }
        }
        1 => {
            let grouping_type = buffer.read_field(4, "sck_subset_grouping_type")? as u8;
            let subset_number = buffer.read_field(5, "sck_subset_number")? as u8;
            let count = buffer.read_field(6, "number_of_sck_status")? as usize;
            let scks = (0..count)
                .map(|_| {
                    Ok(SckStatus {
                        number: buffer.read_field(5, "sck_number")? as u8,
                        version_number: buffer.read_field(16, "sck_version_number")? as u16,
                    })
                })
                .collect::<Result<_, PduParseErr>>()?;
            KeyStatusResponse::Scks {
                grouping_type: Some(grouping_type),
                subset_number: Some(subset_number),
                scks,
            }
        }
        3 | 4 => {
            let count = buffer.read_field(5, "number_of_gck_status")? as usize;
            let gcks = (0..count)
                .map(|_| {
                    Ok(GckStatus {
                        number: buffer.read_field(16, "gck_number")? as u16,
                        version_number: buffer.read_field(16, "gck_version_number")? as u16,
                    })
                })
                .collect::<Result<_, PduParseErr>>()?;
            KeyStatusResponse::Gcks(gcks)
        }
        5 => {
            let count = buffer.read_field(2, "number_of_gsko_status")? as usize;
            KeyStatusResponse::GskoVersions(
                (0..count)
                    .map(|_| buffer.read_field(16, "gsko_version_number").map(|v| v as u16))
                    .collect::<Result<_, _>>()?,
            )
        }
        value => {
            return Err(PduParseErr::InvalidValue {
                field: "key_status_type",
                value: u64::from(value),
            });
        }
    };
    Ok(UKeyStatusResponse {
        response,
        tail: read_tail(buffer)?,
    })
}

fn write_u_key_status_response(value: &UKeyStatusResponse, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    match &value.response {
        KeyStatusResponse::Scks {
            grouping_type,
            subset_number,
            scks,
        } => {
            if scks.len() > 32 {
                return Err(PduParseErr::InvalidValue {
                    field: "number_of_sck_status",
                    value: scks.len() as u64,
                });
            }
            let subset = grouping_type.is_some() || subset_number.is_some();
            if grouping_type.is_some() != subset_number.is_some() {
                return Err(PduParseErr::Inconsistency {
                    field: "sck_subset",
                    reason: "grouping type and subset number must be paired",
                });
            }
            buffer.write_bits(if subset { 1 } else { 2 }, 3);
            if let (Some(grouping), Some(number)) = (grouping_type, subset_number) {
                validate(*grouping, 4, "sck_subset_grouping_type")?;
                validate(*number, 5, "sck_subset_number")?;
                buffer.write_bits(u64::from(*grouping), 4);
                buffer.write_bits(u64::from(*number), 5);
            }
            buffer.write_bits(scks.len() as u64, 6);
            for sck in scks {
                validate(sck.number, 5, "sck_number")?;
                buffer.write_bits(u64::from(sck.number), 5);
                buffer.write_bits(u64::from(sck.version_number), 16);
            }
        }
        KeyStatusResponse::Gcks(gcks) => {
            if gcks.len() > 31 {
                return Err(PduParseErr::InvalidValue {
                    field: "number_of_gck_status",
                    value: gcks.len() as u64,
                });
            }
            buffer.write_bits(4, 3);
            buffer.write_bits(gcks.len() as u64, 5);
            for gck in gcks {
                buffer.write_bits(u64::from(gck.number), 16);
                buffer.write_bits(u64::from(gck.version_number), 16);
            }
        }
        KeyStatusResponse::GskoVersions(versions) => {
            if versions.len() > 3 {
                return Err(PduParseErr::InvalidValue {
                    field: "number_of_gsko_status",
                    value: versions.len() as u64,
                });
            }
            buffer.write_bits(5, 3);
            buffer.write_bits(versions.len() as u64, 2);
            for version in versions {
                buffer.write_bits(u64::from(*version), 16);
            }
        }
    }
    write_tail(&value.tail, buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_u(pdu: UOtar) {
        let mut buffer = BitBuffer::new_autoexpand(512);
        pdu.to_bitbuf(&mut buffer).expect("serialize U-OTAR");
        buffer.seek(0);
        assert_eq!(UOtar::from_bitbuf(&mut buffer).expect("parse U-OTAR"), pdu);
        assert_eq!(buffer.get_len_remaining(), 0);
    }

    fn roundtrip_d(pdu: DOtar) {
        let mut buffer = BitBuffer::new_autoexpand(512);
        pdu.to_bitbuf(&mut buffer).expect("serialize D-OTAR");
        buffer.seek(0);
        assert_eq!(DOtar::from_bitbuf(&mut buffer).expect("parse D-OTAR"), pdu);
        assert_eq!(buffer.get_len_remaining(), 0);
    }

    #[test]
    fn sc2_sck_otar_roundtrips() {
        roundtrip_u(UOtar::SckDemand(USckDemand {
            ksg_number: 3,
            sck_numbers: vec![7, 9],
            tail: OtarTail::default(),
        }));
        roundtrip_d(DOtar::SckProvide(DSckProvide {
            acknowledgement_required: true,
            explicit_response: true,
            max_response_timer: 123,
            session_key: OtarSessionKey::Group { gsko_version_number: 42 },
            keys: vec![SckKeyAndIdentifier {
                sck_number: 7,
                version_number: 2,
                direct_mode: false,
                sealed_key: [0x5a; 15],
            }],
            ksg_number: 3,
            retry_interval: 1,
            tail: OtarTail {
                address_extension: Some(0x12_3456),
                proprietary: None,
            },
        }));
        roundtrip_u(UOtar::SckResult(USckResult {
            results: vec![SckNumberAndResult {
                sck_number: 7,
                provision_result: 3,
                current_version_number: Some(3),
            }],
            tail: OtarTail::default(),
        }));
        roundtrip_d(DOtar::SckReject(DSckReject {
            rejected: vec![SckRejected {
                sck_number: 7,
                reject_reason: 2,
            }],
            retry_interval: 1,
            tail: OtarTail::default(),
        }));
    }

    #[test]
    fn sc2_gsko_bootstrap_roundtrips() {
        roundtrip_u(UOtar::GskoDemand(UGskoDemand { tail: OtarTail::default() }));
        roundtrip_d(DOtar::GskoProvide(DGskoProvide {
            random_seed: [0x11; 10],
            version_number: 2,
            sealed_gsko: [0x22; 15],
            cmg_gssi: 0x00ab_cdef,
            tail: OtarTail::default(),
        }));
        roundtrip_u(UOtar::GskoResult(UGskoResult {
            version_number: 2,
            provision_result: 0,
            cmg_gssi: 0x00ab_cdef,
            tail: OtarTail::default(),
        }));
        roundtrip_d(DOtar::GskoReject(DGskoReject {
            reject_reason: 4,
            cmg_gssi: 0x00ab_cdef,
            retry_interval: 2,
            tail: OtarTail::default(),
        }));
    }

    #[test]
    fn cck_gck_and_key_status_roundtrip() {
        roundtrip_d(DOtar::CckProvide(DCckProvide {
            provision: Some(CckInformation {
                identifier: 9,
                future_key_type: false,
                sealed_key: [0x11; 15],
                location_areas: CckLocationAreas::List(vec![1, 2]),
                future_sealed_key: Some([0x22; 15]),
            }),
            proprietary: None,
        }));
        roundtrip_u(UOtar::CckDemand(UCckDemand {
            location_area: 123,
            proprietary: None,
        }));
        roundtrip_u(UOtar::CckResult(UCckResult {
            provision_result: 0,
            future_provision_result: Some(0),
            proprietary: None,
        }));
        roundtrip_d(DOtar::CckReject(DCckReject {
            reject_reason: 0,
            retry_interval: 1,
            proprietary: None,
        }));

        let gck = GckKeyAndIdentifier {
            gck_number: 3,
            version_number: 4,
            sealed_key: [0x33; 15],
        };
        roundtrip_u(UOtar::GckDemand(UGckDemand {
            ksg_number: 2,
            gck_numbers: vec![3],
            gssis: vec![0x00ab_cdef],
            tail: OtarTail::default(),
        }));
        roundtrip_d(DOtar::GckProvide(DGckProvide {
            acknowledgement_required: true,
            explicit_response: true,
            max_response_timer: 11,
            session_key: OtarSessionKey::Individual { random_seed: [0x44; 10] },
            keys: vec![gck],
            ksg_number: 2,
            association: GroupAssociation::Gssi(0x00ab_cdef),
            retry_interval: 1,
            tail: OtarTail::default(),
        }));
        roundtrip_u(UOtar::GckResult(UGckResult {
            results: vec![GckProvisionResult {
                gck_number: 3,
                version_number: 4,
                provision_result: 3,
                current_version_number: Some(5),
            }],
            tail: OtarTail::default(),
        }));
        roundtrip_d(DOtar::GckReject(DGckReject {
            rejected: vec![GckRejected {
                reject_reason: 1,
                association: GroupAssociation::GckNumber,
            }],
            retry_interval: 1,
            tail: OtarTail::default(),
        }));

        roundtrip_d(DOtar::KeyStatusDemand(DKeyStatusDemand {
            acknowledgement_required: true,
            explicit_response: true,
            max_response_timer: 1,
            request: KeyStatusRequest::SckSubset {
                grouping_type: 2,
                subset_number: 3,
            },
            tail: OtarTail::default(),
        }));
        roundtrip_u(UOtar::KeyStatusResponse(UKeyStatusResponse {
            response: KeyStatusResponse::Scks {
                grouping_type: Some(2),
                subset_number: Some(3),
                scks: vec![SckStatus {
                    number: 7,
                    version_number: 8,
                }],
            },
            tail: OtarTail::default(),
        }));
    }

    #[test]
    fn invalid_conditional_otar_fields_are_rejected() {
        let mut buffer = BitBuffer::new_autoexpand(64);
        assert!(
            UOtar::GckDemand(UGckDemand {
                ksg_number: 0,
                gck_numbers: vec![],
                gssis: vec![],
                tail: OtarTail::default(),
            })
            .to_bitbuf(&mut buffer)
            .is_err()
        );
        assert!(
            UOtar::CckResult(UCckResult {
                provision_result: 8,
                future_provision_result: None,
                proprietary: None,
            })
            .to_bitbuf(&mut buffer)
            .is_err()
        );
    }
}
