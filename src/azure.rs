use crate::{HmacSha256, KeyInfo, RequestInfo};
use base64_light::{base64_decode, base64_encode_bytes};
use chrono::{DateTime, Utc};
use hmac::digest::KeyInit;
use hmac::Mac;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

const VERSION: &str = "2023-11-03";

pub struct AzureKeyInfo {
    account: String,
    key: Vec<u8>
}

impl KeyInfo for AzureKeyInfo {
    fn build_request_info(
        &self,
        method: &str,
        datetime: DateTime<Utc>,
        data: &Vec<u8>,
        path: &String,
        query_parameters: String
    ) -> Result<RequestInfo, Error> {
        let parts: Vec<String> = path.splitn(2, '/').map(|p| p.to_string()).collect();
        if parts.len() == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "empty path"));
        }
        let longdatetime = datetime
            .format("%a, %d %h %Y %H:%M:%S %Z")
            .to_string()
            .replace("UTC", "GMT");
        let mut headers = HashMap::new();
        headers.insert("x-ms-date".to_string(), longdatetime.clone());
        headers.insert("x-ms-version".to_string(), VERSION.to_string());
        let md5_hash = if method == "PUT" {
            let hash = base64_encode_bytes(&md5::compute(data).0);
            headers.insert("x-ms-blob-type".to_string(), "BlockBlob".to_string());
            headers.insert("x-ms-access-tier".to_string(), "Hot".to_string());
            headers.insert("Content-MD5".to_string(), hash.clone());
            hash
        } else {
            String::new()
        };
        let (canonicalized_headers, canonicalized_resource, content_length) = if method == "GET" {
            let query_info = if parts.len() == 1 {
                "\ncomp:list\nrestype:container"
            } else {
                ""
            };
            let (h, v) = self.build_headers_resource_get(longdatetime, path, query_info);
            (h, v, "".to_string())
        } else {
            let (h, v) = self.build_headers_resource_put(longdatetime, path);
            (h, v, data.len().to_string())
        };
        let bearer = format!(
            "SharedKey {}:{}",
            self.account,
            self.build_signature(
                method,
                canonicalized_headers,
                canonicalized_resource,
                content_length,
                md5_hash
            )?
        );
        headers.insert("Authorization".to_string(), bearer);
        let mut url = format!("https://{}.blob.core.windows.net/{}", self.account, path);
        if method == "GET" && parts.len() == 1 {
            url += "?restype=container&comp=list";
        }
        Ok(RequestInfo { url, headers, delete_request: method == "DELETE" })
    }

    fn build_presigned_url(
        &self,
        _method: &str,
        _datetime: DateTime<Utc>,
        _path: &String,
        _expiration: usize,
    ) -> Result<String, Error> {
        todo!()
    }
}

impl AzureKeyInfo {
    pub fn new(account: String, key_string: String) -> Result<AzureKeyInfo, Error> {
        let key = base64_decode(key_string.as_str());
        if key.len() != 64 {
            return Err(Error::new(ErrorKind::InvalidInput, "incorrect azure key"));
        }
        Ok(AzureKeyInfo { account, key })
    }

    fn build_headers_resource_put(&self, date: String, path: &String) -> (String, String) {
        let canonicalized_headers = format!(
            "x-ms-access-tier:Hot\nx-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-version:{}",
            date, VERSION
        );
        let canonicalized_resource = format!("/{}/{}", self.account, path);
        (canonicalized_headers, canonicalized_resource)
    }

    fn build_headers_resource_get(
        &self,
        date: String,
        path: &String,
        query_info: &str,
    ) -> (String, String) {
        let canonicalized_headers = format!("x-ms-date:{}\nx-ms-version:{}", date, VERSION);
        let canonicalized_resource = format!("/{}/{}{}", self.account, path, query_info);
        (canonicalized_headers, canonicalized_resource)
    }

    fn build_signature(
        &self,
        method: &str,
        canonicalized_headers: String,
        canonicalized_resource: String,
        content_length: String,
        md5_hash: String,
    ) -> Result<String, Error> {
        let string_to_sign = format!(
            "{}\n\n\n{}\n{}\n\n\n\n\n\n\n\n{}\n{}",
            method, content_length, md5_hash, canonicalized_headers, canonicalized_resource
        );
        let mut mac: HmacSha256 = KeyInit::new_from_slice(&self.key)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
        mac.update(string_to_sign.as_bytes());
        let hash1 = mac.finalize();
        let bytes1 = hash1.into_bytes();
        Ok(base64_encode_bytes(&bytes1))
    }
}

pub fn build_azure_key_info(parameters: &HashMap<String, String>) -> Result<AzureKeyInfo, Error> {
    let account = parameters.get("account").ok_or(Error::new(ErrorKind::InvalidData, "missing account"))?;
    let key = parameters.get("access_key").ok_or(Error::new(ErrorKind::InvalidData, "missing access_key"))?;
    AzureKeyInfo::new(account.clone(), key.clone())
}
