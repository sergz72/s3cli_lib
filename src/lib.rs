pub mod azure;
mod qs3;

use chrono::{DateTime, Utc};
use hex_encode_rust::{hex_decode, hex_encode};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

const SIGNED_HEADER_STRING: &str = "host;x-amz-content-sha256;x-amz-date";
const S3_SERVICE: &str = "s3";

type HmacSha256 = Hmac<Sha256>;

#[derive(PartialEq, Clone)]
pub enum SourceType {
    AWS,
    GCP,
    Custom,
    CustomNoPrefix,
}

pub trait KeyInfo {
    fn build_request_info(
        &self,
        method: &str,
        datetime: DateTime<Utc>,
        data: &Vec<u8>,
        path: &String,
    ) -> Result<RequestInfo, Error>;
    fn build_presigned_url(
        &self,
        method: &str,
        datetime: DateTime<Utc>,
        path: &String,
        expiration: usize,
    ) -> Result<String, Error>;
}

pub struct S3KeyInfo {
    source_type: SourceType,
    host: Option<String>,
    region: String,
    key: String,
    secret: String,
}

struct S3SignatureBuilder {
    host: String,
    url_path: String,
    url: String,
    longdatetime: String,
    shortdate: String,
}

impl S3SignatureBuilder {
    fn new(key_info: &S3KeyInfo, path: &String, datetime: DateTime<Utc>) -> Result<S3SignatureBuilder, Error> {
        let parts: Vec<String> = path.splitn(2, '/').map(|p| p.to_string()).collect();
        let host = match &key_info.source_type {
            SourceType::AWS => parts[0].clone() + ".s3." + key_info.region.as_str() + ".amazonaws.com",
            SourceType::GCP => parts[0].clone() + ".storage.googleapis.com",
            SourceType::Custom => {
                if let Some(host) = &key_info.host {
                    parts[0].clone() + host.as_str()
                } else {
                    return Err(Error::new(ErrorKind::InvalidInput, "missing host"));
                }
            }
            SourceType::CustomNoPrefix => {
                if let Some(host) = &key_info.host {
                    host.clone()
                } else {
                    return Err(Error::new(ErrorKind::InvalidInput, "missing host"));
                }
            }
        };
        let url_path = "/".to_string()
            + if key_info.source_type == SourceType::CustomNoPrefix {
            path.as_str()
        } else {
            if parts.len() == 2 {
                parts[1].as_str()
            } else {
                ""
            }
        };
        let url = "https://".to_string() + host.as_str() + url_path.as_str();
        let longdatetime = datetime.format("%Y%m%dT%H%M%SZ").to_string();
        let shortdate = datetime.format("%Y%m%d").to_string();

        Ok(S3SignatureBuilder{
            host,
            url_path,
            url,
            longdatetime,
            shortdate,
        })
    }

    fn build_signature(
        &self,
        method: &str,
        key_info: &S3KeyInfo,
        hash: String,
        query_parameters: &String,
        only_use_host: bool,
    ) -> Result<String, Error> {
        let canonical = canonical_request(method, &self.url_path, query_parameters, &self.host, hash, &self.longdatetime, only_use_host);
        let scope = scope_string(&self.shortdate, &key_info.region, S3_SERVICE);
        let string_to_sign = string_to_sign(&self.longdatetime, scope.clone(), &canonical);
        let signing_key = signing_key(&self.shortdate, &key_info.secret, &key_info.region, S3_SERVICE)?;

        let mut mac: HmacSha256 = KeyInit::new_from_slice(&signing_key)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
        mac.update(string_to_sign.as_bytes());
        let hash1 = mac.finalize();
        let bytes1 = hash1.into_bytes();
        let signature = hex_encode(&bytes1.as_slice());

        if only_use_host {
            return Ok(signature);
        }
        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            key_info.key, scope, SIGNED_HEADER_STRING, signature
        ))
    }
}

impl KeyInfo for S3KeyInfo {
    fn build_request_info(
        &self,
        method: &str,
        datetime: DateTime<Utc>,
        data: &Vec<u8>,
        path: &String,
    ) -> Result<RequestInfo, Error> {
        let builder = S3SignatureBuilder::new(&self, path, datetime)?;
        let mut headers = HashMap::new();
        headers.insert("X-Amz-Date".to_string(), builder.longdatetime.clone());
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex_encode(hasher.finalize().as_slice());
        headers.insert("x-amz-content-sha256".to_string(), hash.clone());
        let signature = builder.build_signature(method, &self, hash, &"".to_string(), false)?;
        headers.insert("Authorization".to_string(), signature);
        Ok(RequestInfo { url: builder.url.clone(), headers })
    }

    fn build_presigned_url(
        &self,
        method: &str,
        datetime: DateTime<Utc>,
        path: &String,
        expiration: usize,
    ) -> Result<String, Error> {
        let builder = S3SignatureBuilder::new(&self, path, datetime)?;
        let query_parameters = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}%2F{}%2F{}%2Fs3%2Faws4_request&X-Amz-Date={}&X-Amz-Expires={}&X-Amz-SignedHeaders=host",
            self.key, builder.shortdate, self.region, builder.longdatetime, expiration);
        let signature =
            builder.build_signature(method, &self, "UNSIGNED-PAYLOAD".to_string(), &query_parameters, true)?;
        Ok(format!("{}?{}&X-Amz-Signature={}", builder.url, query_parameters, signature))
    }
}

impl S3KeyInfo {
    pub fn new(
        source_type: SourceType,
        host: Option<String>,
        region: String,
        key: String,
        secret: String,
    ) -> S3KeyInfo {
        S3KeyInfo {
            source_type,
            host,
            region,
            key,
            secret,
        }
    }

    pub fn new_from_key_info(key_info: &S3KeyInfo, secret: String) -> Result<S3KeyInfo, Error> {
        let hash = hex_decode(&key_info.secret)?;
        if hash.len() != 32 {
            return Err(Error::new(ErrorKind::InvalidData, "wrong hash size"));
        }

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        if hash != hasher.finalize().to_vec() {
            return Err(Error::new(ErrorKind::InvalidData, "s3 secret hash does not match"));
        }

        Ok(S3KeyInfo{
            source_type: key_info.source_type.clone(),
            host: key_info.host.clone(),
            region: key_info.region.clone(),
            key: key_info.key.clone(),
            secret
        })
    }
}

fn signing_key(
    shortdate: &String,
    secret_key: &String,
    region: &String,
    service: &str,
) -> Result<Vec<u8>, Error> {
    let secret = "AWS4".to_string() + secret_key.as_str();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&secret.as_bytes())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(shortdate.as_bytes());
    let date_tag = mac.finalize();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&date_tag.into_bytes())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(region.as_bytes());
    let region_tag = mac.finalize();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&region_tag.into_bytes())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(service.as_bytes());
    let service_tag = mac.finalize();

    let mut mac: HmacSha256 = KeyInit::new_from_slice(&service_tag.into_bytes())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(b"aws4_request");
    let signing_tag = mac.finalize();

    Ok(signing_tag.into_bytes().to_vec())
}

fn canonical_request(
    method: &str,
    url_path: &String,
    query_parameters: &String,
    host: &String,
    hash: String,
    longdatetime: &String,
    only_use_host: bool
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n\n{}\n{}",
        method,
        url_path,
        query_parameters,
        canonical_header_string(host, hash.clone(), longdatetime, only_use_host),
        if only_use_host {"host"} else {SIGNED_HEADER_STRING},
        hash
    )
}

fn canonical_header_string(host: &String, hash: String, longdatetime: &String, only_use_host: bool)
    -> String {
    if only_use_host {
        return format!("host:{}", host);
    }
    format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}",
        host, hash, longdatetime
    )
}

fn string_to_sign(longdatetime: &String, scope: String, canonical_req: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_req.as_bytes());
    let hash = hasher.finalize();
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        longdatetime,
        scope,
        hex_encode(hash.as_slice())
    )
}

fn scope_string(shortdate: &String, region: &String, service: &str) -> String {
    format!("{}/{}/{}/aws4_request", shortdate, region, service)
}

pub struct RequestInfo {
    pub url: String,
    pub headers: HashMap<String, String>,
}

impl RequestInfo {
    pub fn make_request(&self, data: Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let mut request = if data.is_some() {
            minreq::put(&self.url).with_body(data.unwrap())
        } else {
            minreq::get(&self.url)
        };
        for (k, v) in &self.headers {
            request = request.with_header(k, v);
        }
        let res = request
            .send()
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        let status_code = res.status_code;
        let data = res.into_bytes();
        if status_code != 200 && status_code != 201 {
            let body =
                String::from_utf8(data).unwrap_or("could not parse body to string".to_string());
            let error_message = format!("wrong status code {}\n{}", status_code, body);
            return Err(Error::new(ErrorKind::Other, error_message));
        }
        Ok(data)
    }
}

pub fn build_key_info(data: Vec<u8>) -> Result<S3KeyInfo, Error> {
    let text =
        String::from_utf8(data).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let lines: Vec<String> = text
        .split('\n')
        .map(|v| v.to_string().trim().to_string())
        .collect();
    if lines.len() < 4
        || lines[0].is_empty()
        || lines[1].is_empty()
        || lines[2].is_empty()
        || lines[3].is_empty()
    {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect key file"));
    }
    let (source_type, host) = match lines[0].as_str() {
        "aws" => (SourceType::AWS, None),
        "gcp" => (SourceType::GCP, None),
        _ => {
            let parts: Vec<&str> = lines[0].splitn(3, ' ').collect();
            if parts[0] == "custom" {
                if parts.len() == 2 {
                    (SourceType::Custom, Some(".".to_string() + parts[1]))
                } else if parts[1] == "noprefix" {
                    (SourceType::CustomNoPrefix, Some(parts[2].to_string()))
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "unknown source type modifier",
                    ));
                }
            } else {
                return Err(Error::new(ErrorKind::InvalidData, "unknown source type"));
            }
        }
    };
    Ok(S3KeyInfo::new(
        source_type,
        host,
        lines[1].clone(),
        lines[2].clone(),
        lines[3].clone(),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use crate::{build_key_info, KeyInfo, S3KeyInfo, SourceType};
    use chrono::TimeZone;
    use std::io::Error;

    #[test]
    fn test_build_request_info() -> Result<(), Error> {
        let key_info = S3KeyInfo::new(
            SourceType::AWS,
            None,
            "us-east-1".to_string(),
            "key1234567890".to_string(),
            "secret1234567890".to_string(),
        );
        let path = "test/".to_string();
        let now = chrono::Utc
            .with_ymd_and_hms(2023, 11, 5, 20, 14, 0)
            .unwrap();
        let request_info = key_info.build_request_info("GET", now.clone(), &Vec::new(), &path)?;
        assert_eq!(request_info.url, "https://test.s3.us-east-1.amazonaws.com/");
        assert_eq!(request_info.headers.len(), 3);
        //assert_eq!(request_info.headers.get("host").unwrap().as_str(), "test.s3.amazonaws.com");
        assert_eq!(
            request_info.headers.get("X-Amz-Date").unwrap().as_str(),
            "20231105T201400Z"
        );
        assert_eq!(
            request_info
                .headers
                .get("x-amz-content-sha256")
                .unwrap()
                .as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(request_info.headers.get("Authorization").unwrap().as_str(),
                   "AWS4-HMAC-SHA256 Credential=key1234567890/20231105/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=563f38c986978b549b37e6625ab0cd1896b4cbb9500c41b4f07abc6f4499e599");
        Ok(())
    }

    #[test]
    fn test_build_presigned_url() -> Result<(), Error> {
        let key_info = S3KeyInfo::new(
            SourceType::AWS,
            None,
            "us-east-1".to_string(),
            "key1234567890".to_string(),
            "secret1234567890".to_string(),
        );
        let path = "pdbf/file.txt".to_string();
        let now = chrono::Utc
            .with_ymd_and_hms(2023, 11, 27, 18, 13, 18)
            .unwrap();
        let url = key_info.build_presigned_url("GET", now.clone(), &path, 60)?;
        assert_eq!(url, "https://pdbf.s3.us-east-1.amazonaws.com/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key1234567890%2F20231127%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20231127T181318Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=a19704408c6cc588423f5932a809185fbaf35ceb66e552244b9cf86fd40ff5d5");
        Ok(())
    }
}
