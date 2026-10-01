use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use toml::Value;

#[derive(Debug, Clone)]
pub struct CfgWeb {
    pub enabled: bool,
    pub bind_address: IpAddr,
    pub port: u16,
}

impl Default for CfgWeb {
    fn default() -> Self {
        Self { enabled: false, bind_address: "0.0.0.0".parse().unwrap(), port: 8080 }
    }
}

#[derive(Default, Deserialize)]
pub struct CfgWebDto {
    pub enabled: Option<bool>,
    pub bind_address: Option<String>,
    pub port: Option<u16>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl TryFrom<CfgWebDto> for CfgWeb {
    type Error = String;

    fn try_from(dto: CfgWebDto) -> Result<Self, Self::Error> {
        if !dto.extra.is_empty() {
            let mut keys = dto.extra.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            return Err(format!("Unrecognized fields in web: {keys:?}"));
        }
        let mut result = Self::default();
        result.enabled = dto.enabled.unwrap_or(false);
        if let Some(address) = dto.bind_address {
            result.bind_address = address.parse().map_err(|_| "web.bind_address must be an IP address".to_owned())?;
        }
        result.port = dto.port.unwrap_or(8080);
        if result.port == 0 {
            return Err("web.port must be 1-65535".to_owned());
        }
        Ok(result)
    }
}
