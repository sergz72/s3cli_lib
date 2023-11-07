use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use chrono::{DateTime, Utc};
use hex_encode_rust::hex_encode;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

const SIGNED_HEADER_STRING: &str = "host;x-amz-content-sha256;x-amz-date";
const S3_SERVICE: &str = "s3";

type HmacSha256 = Hmac<Sha256>;

pub enum SourceType {
    AWS,
    GCP,
    Custom
}

pub struct KeyInfo {
    source_type: SourceType,
    host: Option<String>,
    region: String,
    key: String,
    secret: String
}

impl KeyInfo {
    pub fn new(source_type: SourceType, host: Option<String>, region: String, key: String,
               secret: String) -> KeyInfo {
        KeyInfo{
            source_type,
            host,
            region,
            key,
            secret,
        }
    }

    pub fn build_request_info(&self, method: &str, datetime: DateTime<Utc>, data: &Vec<u8>,
                          path: &String) -> Result<RequestInfo, Error> {
        let parts: Vec<String> = path.splitn(2, '/').map(|p| p.to_string()).collect();
        let host = parts[0].clone() + match &self.source_type {
            SourceType::AWS => ".s3.amazonaws.com",
            SourceType::GCP => ".storage.googleapis.com",
            SourceType::Custom => {
                if let Some(host) = &self.host {
                    host.as_str()
                } else {
                    return Err(Error::new(ErrorKind::InvalidInput, "missing host"))
                }
            }
        };
        let file_name = if parts.len() == 2 { parts[1].as_str() } else { "" };
        let url_path = "/".to_string() + file_name;
        let url = "https://".to_string() + host.as_str() + url_path.as_str();
        let longdatetime = datetime.format("%Y%m%dT%H%M%SZ").to_string();
        let shortdate = datetime.format("%Y%m%d").to_string();
        let mut headers = HashMap::new();
        headers.insert(
            "X-Amz-Date".to_string(),
            longdatetime.clone()
        );
        //headers.insert("host".to_string(), host.clone());
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex_encode(hasher.finalize().as_slice());
        headers.insert("x-amz-content-sha256".to_string(), hash.clone());
        let signature = self.build_signature(method, url_path, longdatetime,
                                             shortdate, host, hash)?;
        headers.insert("Authorization".to_string(), signature);
        Ok(RequestInfo{ url, headers })
    }

    fn build_signature(&self, method: &str, url_path: String, longdatetime: String,
                       shortdate: String, host: String, hash: String) -> Result<String, Error> {
        let canonical = canonical_request(method, url_path, host, hash, &longdatetime);
        let scope = scope_string(&shortdate, &self.region, S3_SERVICE);
        let string_to_sign = string_to_sign(longdatetime, scope.clone(), &canonical);
        let signing_key = signing_key(shortdate, &self.secret, &self.region, S3_SERVICE)?;

        let mut mac: HmacSha256 = KeyInit::new_from_slice(&signing_key)
            .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
        mac.update(string_to_sign.as_bytes());
        let hash1 = mac.finalize();
        let bytes1 = hash1.into_bytes();
        let signature = hex_encode(&bytes1.as_slice());

        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            self.key,
            scope,
            SIGNED_HEADER_STRING,
            signature
        ))
    }
}

fn signing_key(
    shortdate: String,
    secret_key: &String,
    region: &String,
    service: &str,
) -> Result<Vec<u8>, Error> {
    let secret = "AWS4".to_string() + secret_key.as_str();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&secret.as_bytes())
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(shortdate.as_bytes());
    let date_tag = mac.finalize();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&date_tag.into_bytes())
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(region.as_bytes());
    let region_tag = mac.finalize();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&region_tag.into_bytes())
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(service.as_bytes());
    let service_tag = mac.finalize();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&service_tag.into_bytes())
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(b"aws4_request");
    let signing_tag = mac.finalize();

    Ok(signing_tag.into_bytes().to_vec())
}

fn canonical_request(method: &str, url_path: String, host: String, hash: String,
                     longdatetime: &String) -> String {
    format!(
        "{}\n{}\n\n{}\n\n{}\n{}",
        method,
        url_path,
        canonical_header_string(host, hash.clone(), longdatetime),
        SIGNED_HEADER_STRING,
        hash
    )
}

fn canonical_header_string(host: String, hash: String, longdatetime: &String) -> String {
    format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}", host, hash, longdatetime)
}

fn string_to_sign(longdatetime: String, scope: String, canonical_req: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_req.as_bytes());
    let hash = hasher.finalize();
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        longdatetime,
        scope,
        hex_encode(hash.as_slice()))
}

fn scope_string(shortdate: &String, region: &String, service: &str) -> String {
    format!(
        "{}/{}/{}/aws4_request",
        shortdate,
        region,
        service
    )
}

pub struct RequestInfo {
    pub url: String,
    pub headers: HashMap<String, String>
}

impl RequestInfo {
    pub fn make_request(&self, data: Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let mut request = if data.is_some() {
            minreq::put(&self.url).with_body(data.unwrap())
        } else {minreq::get(&self.url)};
        for (k, v) in &self.headers {
            request = request.with_header(k, v);
        }
        let res = request
            .send()
            .map_err(|e|Error::new(ErrorKind::Other, e.to_string()))?;
        let status_code = res.status_code;
        let data = res.into_bytes();
        if status_code != 200 {
            let body = String::from_utf8(data)
                .unwrap_or("could not parse body to string".to_string());
            let error_message =
                format!("wrong status code {}\n{}", status_code, body);
            return Err(Error::new(ErrorKind::Other, error_message));
        }
        Ok(data)
    }
}

pub fn build_key_info(data: Vec<u8>) -> Result<KeyInfo, Error> {
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let lines: Vec<String> = text.split('\n')
        .map(|v|v.to_string().trim().to_string())
        .collect();
    if lines.len() < 4 || lines[0].is_empty() || lines[1].is_empty() || lines[2].is_empty() ||
        lines[3].is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect key file"));
    }
    let (source_type, host) = match lines[0].as_str() {
        "aws" => (SourceType::AWS, None),
        "gcp" => (SourceType::GCP, None),
        _ => {
            let parts: Vec<&str> = lines[0].splitn(2, ' ').collect();
            if parts.len() == 2 && parts[0] == "custom" {
                (SourceType::Custom, Some(".".to_string() + parts[1]))
            } else {
                return Err(Error::new(ErrorKind::InvalidData, "unknown source type"))
            }
        }
    };
    Ok(KeyInfo::new(
        source_type,
        host,
        lines[1].clone(),
        lines[2].clone(),
        lines[3].clone(),
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use chrono::TimeZone;
    use crate::{KeyInfo, SourceType};

    #[test]
    fn test_build_request_info() -> Result<(), Error> {
        let key_info = KeyInfo::new(
            SourceType::AWS,
            None,
            "us-east-1".to_string(),
            "key1234567890".to_string(),
            "secret1234567890".to_string()
        );
        let path = "test/".to_string();
        let now = chrono::Utc.with_ymd_and_hms(2023, 11, 5, 20, 14, 0).unwrap();
        let request_info = key_info.build_request_info("GET",
                                                       now.clone(),
                                                       &Vec::new(), &path)?;
        assert_eq!(request_info.url, "https://test.s3.amazonaws.com/");
        assert_eq!(request_info.headers.len(), 3);
        //assert_eq!(request_info.headers.get("host").unwrap().as_str(), "test.s3.amazonaws.com");
        assert_eq!(request_info.headers.get("X-Amz-Date").unwrap().as_str(), "20231105T201400Z");
        assert_eq!(request_info.headers.get("x-amz-content-sha256").unwrap().as_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(request_info.headers.get("Authorization").unwrap().as_str(),
                   "AWS4-HMAC-SHA256 Credential=key1234567890/20231105/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=9163c1d7bc7737bc66f38363098b6f67dcbb0fd2500ea52607b21e0c62c75dd7");
        Ok(())
    }
}
