use std::io::Error;
use chrono::{DateTime, Utc};
use crate::{KeyInfo, RequestInfo};

pub struct QKeyInfo {
    host_name: String,
    port: u16,
    rsa_public_key: String,
    s3_password: String
}

impl KeyInfo for QKeyInfo {
    fn build_request_info(
        &self,
        method: &str,
        datetime: DateTime<Utc>,
        data: &Vec<u8>,
        path: &String,
    ) -> Result<RequestInfo, Error> {
        todo!()
    }

    fn build_presigned_url(
        &self,
        method: &str,
        datetime: DateTime<Utc>,
        path: &String,
        expiration: usize,
    ) -> Result<String, Error> {
        todo!()
    }
}

impl QKeyInfo {
    pub fn new(data: Vec<u8>) -> Result<QKeyInfo, Error> {
        Ok(QKeyInfo{
            host_name: "".to_string(),
            port: 0,
            rsa_public_key: "".to_string(),
            s3_password: "".to_string(),
        })
    }
}
