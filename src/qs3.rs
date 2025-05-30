use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use chrono::{DateTime, Utc};
use qs3_lib::client::ServerConfig;
use crate::{KeyInfo, RequestInfo};

pub struct QKeyInfo {
    server_config: ServerConfig,
    rsa_key: String,
    read_timeout: u64,
    retries: usize
}

impl KeyInfo for QKeyInfo {
    fn build_request_info(
        &self,
        method: &str,
        _datetime: DateTime<Utc>,
        _data: &Vec<u8>,
        path: &String,
        query_parameters: String,
        additional_headers: &HashMap<String, String>
    ) -> Result<RequestInfo, Error> {
        let method = match method {
            "GET" => 0u8,
            "PUT" => 1u8,
            _ => return Err(Error::new(ErrorKind::InvalidInput, "invalid method"))
        };
        let response = self.server_config.qsend(self.rsa_key.as_str(), method, path,
                                                self.read_timeout, self.retries)?;
        let url = String::from_utf8(response)
            .map_err(|_e|Error::new(ErrorKind::InvalidData, "incorrect response from server"))?;
        Ok(RequestInfo{ url, headers: HashMap::new(), delete_request: false })
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

impl QKeyInfo {
    pub fn new(data: Vec<u8>, rsa_key: String, read_timeout: u64, retries: usize)
        -> Result<QKeyInfo, Error> {
        let server_config = ServerConfig::new(data)?;
        Ok(QKeyInfo{ server_config, rsa_key, read_timeout, retries })
    }
}
