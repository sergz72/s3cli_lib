use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use base64_light::{base64_decode, base64_encode_bytes};
use chrono::{DateTime, Utc};
use hmac::digest::KeyInit;
use hmac::Mac;
use crate::{HmacSha256, KeyInfo, RequestInfo};

const VERSION: &str = "2023-11-03";

pub struct AzureKeyInfo {
    account: String,
    key: Vec<u8>
}

impl KeyInfo for AzureKeyInfo {
    fn build_request_info(&self, method: &str, datetime: DateTime<Utc>, _data: &Vec<u8>,
                          path: &String) -> Result<RequestInfo, Error> {
        let parts: Vec<String> = path.splitn(2, '/').map(|p| p.to_string()).collect();
        if parts.len() == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "empty path"));
        }
        let container = parts[0].clone();
        //let file_name = parts[1].clone();
        let longdatetime = datetime.format("%a, %d %h %Y %H:%M:%S %Z").to_string()
            .replace("UTC", "GMT");
        let mut headers = HashMap::new();
        headers.insert("x-ms-date".to_string(), longdatetime.clone());
        headers.insert("x-ms-version".to_string(), VERSION.to_string());
        let bearer = format!("SharedKey {}:{}", self.account,
                             self.build_signature(method, longdatetime, container)?);
        headers.insert("Authorization".to_string(), bearer);
        let url = format!("https://{}.blob.core.windows.net/{}?restype=container&comp=list",
                          self.account, path);
        Ok(RequestInfo{ url, headers })
    }
}

impl AzureKeyInfo {
    pub fn new(account: String, key_string: String) -> Result<AzureKeyInfo, Error> {
        let key = base64_decode(key_string.as_str());
        if key.len() != 64 {
            return Err(Error::new(ErrorKind::InvalidInput, "incorrect azure key"));
        }
        Ok(AzureKeyInfo{ account, key })
    }

    fn build_signature(&self, method: &str, date: String, container: String) -> Result<String, Error> {
        let canonicalized_headers = format!("x-ms-date:{}\nx-ms-version:{}", date, VERSION);
        let canonicalized_resource=format!("/{}/{}\ncomp:list\nrestype:container",
                                           self.account, container);
        let string_to_sign = format!("{}\n\n\n\n\n\n\n\n\n\n\n\n{}\n{}",
                                     method, canonicalized_headers, canonicalized_resource);
        let mut mac: HmacSha256 = KeyInit::new_from_slice(&self.key)
            .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
        mac.update(string_to_sign.as_bytes());
        let hash1 = mac.finalize();
        let bytes1 = hash1.into_bytes();
        Ok(base64_encode_bytes(&bytes1))
    }
}

pub fn build_azure_key_info(data: Vec<u8>) -> Result<AzureKeyInfo, Error> {
    let text = String::from_utf8(data)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let lines: Vec<String> = text.split('\n')
        .map(|v| v.to_string().trim().to_string())
        .collect();
    if lines.len() < 2 || lines[0].is_empty() || lines[1].is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect key file"));
    }
    AzureKeyInfo::new(lines[0].clone(), lines[1].clone())
}
