use serde::Deserialize;
use std::collections::HashMap;
use toml::Value;

/// TTR 001-17 radio-user identity requested during registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CfgRuiType {
    Run,
    Ssi,
    MsIsdn,
    #[default]
    AlphaTag,
}

impl CfgRuiType {
    /// Requested radio-user-assignment value from TTR 001-17 table 1.
    pub const fn assignment_request(self) -> u8 {
        match self {
            Self::Run => 0b001,
            Self::Ssi => 0b010,
            Self::MsIsdn => 0b011,
            Self::AlphaTag => 0b100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CfgRua {
    pub requested_rui_type: CfgRuiType,
}

#[derive(Debug, Deserialize, Default)]
pub struct CfgRuaDto {
    #[serde(default)]
    pub requested_rui_type: CfgRuiType,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

pub fn apply_rua_patch(src: CfgRuaDto) -> CfgRua {
    CfgRua {
        requested_rui_type: src.requested_rui_type,
    }
}

#[cfg(test)]
mod tests {
    use super::{CfgRuaDto, CfgRuiType, apply_rua_patch};

    #[test]
    fn parses_every_supported_requested_rui_type() {
        for (name, expected) in [
            ("run", CfgRuiType::Run),
            ("ssi", CfgRuiType::Ssi),
            ("ms_isdn", CfgRuiType::MsIsdn),
            ("alpha_tag", CfgRuiType::AlphaTag),
        ] {
            let dto: CfgRuaDto = toml::from_str(&format!("requested_rui_type = \"{name}\"")).expect("supported RUI type");
            assert_eq!(apply_rua_patch(dto).requested_rui_type, expected);
        }
    }

    #[test]
    fn defaults_to_alpha_tag_and_rejects_unknown_types() {
        let default: CfgRuaDto = toml::from_str("").expect("default RUA profile");
        assert_eq!(apply_rua_patch(default).requested_rui_type, CfgRuiType::AlphaTag);
        assert!(toml::from_str::<CfgRuaDto>("requested_rui_type = \"email\"").is_err());
    }
}
