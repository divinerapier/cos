use std::{collections::HashMap, fmt::Debug, fs::OpenOptions, ops::Index, sync::Arc};

use form_urlencoded::Parse;
use hyper::{
    client::connect::Connect,
    header::{HeaderValue, AUTHORIZATION},
    HeaderMap, Request, Response, Uri,
};
use openssl::string;
use reqwest::IntoUrl;

use anyhow::Result;

pub struct Client {
    inner: Arc<ClientImpl>,
}

pub(crate) struct ClientImpl {
    access_key: String,
    secret_key: String,

    bucket_url: String,

    inner: reqwest::Client,
}

struct AuthorizationComputer {}

impl AuthorizationComputer {
    fn authorazation(
        secret_id: &str,
        secret_key: &str,
        uri: &str,
        auth_time: AuthTime,
        headers: &HeaderMap,
        queries: Parse,
    ) -> Result<String> {
        let sign_time = auth_time.sign();
        let key_time = auth_time.key();
        let sign_key = Self::calc_sign_key(secret_id, &key_time);
        let (format_headers, signed_header_list) = Self::gen_format_headers(headers)?;
        let (format_parameters, signed_parameter_list) = Self::gen_format_parameters(queries)?;
        let format_string = format!(
            "{}\n{}\n{}\n{}\n",
            "get", uri, &format_parameters, &format_headers
        );
        let string_to_sign = Self::cal_string_to_sign("sha1", &key_time, &format_string);
        let signature = Self::cal_signature(sign_key.as_bytes(), string_to_sign.as_bytes());

        let auth = format! (       "q-sign-algorithm={}&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}" , "sha1",
  secret_id,
  sign_time,
key_time,
signed_header_list.join(";"),
signed_parameter_list.join(";"),
signature);
        Ok(auth)
    }

    fn cal_string_to_sign(alg: &str, sign_time: &str, format_string: &str) -> String {
        let mut sha1 = openssl::sha::Sha1::new();
        sha1.update(&format_string.as_bytes());
        let result = sha1.finish();
        format!("{}\n{}\n{}\n", alg, sign_time, hex::encode(&result))
    }

    fn cal_signature(sign_key: &[u8], string_to_sign: &[u8]) -> String {
        let result = hmacsha1::hmac_sha1(sign_key, string_to_sign);
        hex::encode(&result)
    }

    fn calc_sign_key(sk: &str, key_time: &str) -> String {
        let result = hmacsha1::hmac_sha1(sk.as_bytes(), key_time.as_bytes());
        hex::encode(result)
    }

    fn ishex(c: char) -> bool {
        match c {
            '0'..='9' => true,
            'a'..='f' => true,
            'A'..='F' => true,
            _ => false,
        }
    }

    fn is_valid_query(s: &str) -> bool {
        let index = s.find('%');
        if index.is_none() {
            return true;
        }
        let index = index.unwrap();
        if index + 2 > s.len() {
            return false;
        }
        if !Self::ishex(s.chars().nth(index + 1).unwrap()) {
            return false;
        }
        if Self::ishex(s.chars().nth(index + 1).unwrap()) {
            return false;
        }
        let s = &s[index + 2..];
        s.is_empty() || Self::is_valid_query(s)
    }

    fn gen_format_headers(headers: &HeaderMap) -> Result<(String, Vec<String>)> {
        let mut keys = vec![];
        let mut kv_pairs = HashMap::new();
        let mut header_list = vec![];
        for (key, values) in headers.iter() {
            let key = key.as_str().to_lowercase();
            if !Self::is_sign_header(&key) {
                continue;
            }
            let value = values.to_str()?.to_string();
            keys.push(key.clone());
            kv_pairs.entry(key).or_insert_with(Vec::new).push(value);
        }

        keys.sort();

        for key in keys.iter() {
            if let Some(values) = kv_pairs.get_mut(key) {
                values.sort();
                for value in values {
                    // TODO:
                    header_list.push(format!(
                        "{}={}",
                        crate::urlencoding::safe_url_encode(key),
                        crate::urlencoding::safe_url_encode(value)
                    ))
                }
                kv_pairs.remove(key);
            }
        }

        Ok((header_list.join("&"), keys))
    }

    fn gen_format_parameters(parse: Parse) -> Result<(String, Vec<String>)> {
        let mut keys = vec![];
        let mut kv_pairs = HashMap::new();
        let mut header_list = vec![];
        for (key, values) in parse {
            let key = key.to_ascii_lowercase();
            if !Self::is_valid_query(values.as_ref()) {
                continue;
            }
            if Self::is_ci_parameter(&key) {
                continue;
            }
            let value = values.to_string();
            keys.push(key.clone());
            kv_pairs.entry(key).or_insert_with(Vec::new).push(value);
        }

        keys.sort();

        for key in keys.iter() {
            if let Some(values) = kv_pairs.get_mut(key) {
                values.sort();
                for value in values {
                    // TODO:
                    header_list.push(format!(
                        "{}={}",
                        crate::urlencoding::safe_url_encode(key),
                        crate::urlencoding::safe_url_encode(value)
                    ))
                }
                kv_pairs.remove(key);
            }
        }

        Ok((header_list.join("&"), keys))
    }

    fn is_ci_parameter(name: &str) -> bool {
        name.starts_with("imagemogr2/")
            || name.starts_with("watermark/")
            || name.starts_with("imageview2/")
    }

    fn is_sign_header(name: &str) -> bool {
        let mut m = HashMap::new();
        m.insert("host", true);
        m.insert("range", true);
        m.insert("x-cos-acl", true);
        m.insert("x-cos-grant-read", true);
        m.insert("x-cos-grant-write", true);
        m.insert("x-cos-grant-full-control", true);
        m.insert("response-content-type", true);
        m.insert("response-content-language", true);
        m.insert("response-expires", true);
        m.insert("response-cache-control", true);
        m.insert("response-content-disposition", true);
        m.insert("response-content-encoding", true);
        m.insert("cache-control", true);
        m.insert("content-disposition", true);
        m.insert("content-encoding", true);
        m.insert("content-type", true);
        m.insert("content-length", true);
        m.insert("content-md5", true);
        m.insert("expect", true);
        m.insert("expires", true);
        m.insert("x-cos-content-sha1", true);
        m.insert("x-cos-storage-class", true);
        m.insert("if-modified-since", true);
        m.insert("origin", true);
        m.insert("access-control-request-method", true);
        m.insert("access-control-request-headers", true);
        m.insert("x-cos-object-type", true);
        m.contains_key(name) || name.starts_with("x-cos-")
    }
}

struct AuthTime {
    sign_start_time: i64,
    sign_end_time: i64,
    key_start_time: i64,
    key_end_time: i64,
}

impl AuthTime {
    fn new(start_timestamp: i64, expire_in_secret: i64) -> AuthTime {
        AuthTime {
            sign_start_time: start_timestamp,
            sign_end_time: start_timestamp + expire_in_secret,
            key_start_time: start_timestamp,
            key_end_time: start_timestamp + expire_in_secret,
        }
    }

    fn sign(&self) -> String {
        format!("{};{}", self.sign_start_time, self.sign_end_time)
    }

    fn key(&self) -> String {
        format!("{};{}", self.key_start_time, self.key_end_time)
    }
}

impl ClientImpl {
    pub(crate) fn auth(
        &self,
        begin_timestamp: i64,
        expire_in_second: i64,
        uri: &str,
        headers: &HeaderMap,
        queries: Parse,
    ) -> String {
        let ak = &self.access_key;
        let sk = &self.secret_key;

        let auth_time = AuthTime::new(begin_timestamp, expire_in_second);

        AuthorizationComputer::authorazation(ak, sk, uri, auth_time, headers, queries).unwrap()
    }

    pub async fn get<U: IntoUrl>(&self, url: U) -> Result<reqwest::Response> {
        let now = chrono::Local::now().timestamp();
        let expire = 180 * 24 * 3600;
        let url_str = url.as_str().to_string();
        let builder = self.inner.get(url);
        let mut request = builder.build()?;
        let queries = request.url().query_pairs();
        let auth = self.auth(now, expire, &url_str, request.headers(), queries);
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_str(&auth)?)
            .unwrap();
        Ok(self.inner.execute(request).await?)
    }
}

#[derive(Default)]
pub struct Builder {
    bucket: Option<String>,
    region: Option<String>,
    access_key: Option<String>,
    secret_key: Option<String>,
    max_idle_per_host: Option<usize>,
}

impl Builder {
    pub fn new() -> Builder {
        Default::default()
    }

    pub fn set_bucket<S: Into<String>>(mut self, bucket: S) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    pub fn set_region<S: Into<String>>(mut self, region: S) -> Self {
        self.region = Some(region.into());
        self
    }

    pub fn set_access_key<S: Into<String>>(mut self, access_key: S) -> Self {
        self.access_key = Some(access_key.into());
        self
    }

    pub fn set_secret_key<S: Into<String>>(mut self, secret_key: S) -> Self {
        self.secret_key = Some(secret_key.into());
        self
    }

    pub fn build(self) -> anyhow::Result<Client> {
        let inner = reqwest::Client::builder()
            .pool_max_idle_per_host(self.max_idle_per_host.unwrap_or(100))
            .build()?;

        let bucket_url = format!(
            "https://{}.cos.{}.myqcloud.com",
            self.bucket.unwrap(),
            self.region.unwrap(),
        );

        Ok(Client {
            inner: Arc::new(ClientImpl {
                access_key: self.access_key.unwrap(),
                secret_key: self.secret_key.unwrap(),
                bucket_url,
                inner,
            }),
        })
    }
}

impl Client {
    pub fn bucket(&self) -> BucketService {
        BucketService {
            client: self.inner.clone(),
        }
    }
}

pub struct BucketService {
    client: Arc<ClientImpl>,
}

pub struct BucketGetOptions {
    prefix: String,
    delimiter: String,
    encoding_type: String,
    marker: String,
    max_keys: String,
}

impl BucketService {
    pub async fn get(&self) -> reqwest::Response {
        let client = self.client.clone();
        let now = chrono::Local::now().timestamp();
        // client.auth(now, 180 * 30 * 3600, headers);
        let builder = client.inner.get("https://www.baidu.com");
        let request = builder.build().unwrap();
        client.inner.execute(request).await.unwrap()
        // builder.send().await.unwrap()
    }
}

#[cfg(test)]
mod test {
    use hyper::http::request;

    use super::*;
    #[test]
    fn test_cal_sign_key() {
        let cases = vec![
            (
                "0",
                "hello world",
                "efe8d13a7bcbacdd4052c49f1364450964f10a91",
            ),
            (
                "sdfsdfsdfa12",
                "90uid09fvbndno",
                "c6ca3adc5768d8285d976e253b065f3b791e3787",
            ),
            (
                "xdv8u908jhsdvHIUHI",
                "OIJHoiojhio0909890KLJLIK",
                "2d6f7f99ef83eccb27bcf619a2814e71727c27ef",
            ),
        ];
        for case in cases {
            let result = AuthorizationComputer::calc_sign_key(case.0, case.1);
            assert_eq!(case.2, &result);
        }
    }

    #[test]
    fn test_http_header() {
        let mut header = HeaderMap::new();
        header.append("key0", HeaderValue::from_static("val0-0"));
        header.append("key0", HeaderValue::from_static("val0-1"));
        header.append("key0", HeaderValue::from_static("val0-2"));

        for (key, values) in header.iter() {
            println!("key: {:?}  values: {:?}", key, values);
        }

        println!("{:?}", header);
        // println!("{:?}", header.get("key0").as_ref().unwrap());
        println!("{:?}", header.get_all("key0"));
    }

    #[tokio::test]
    async fn test_queries() {
        let client = reqwest::Client::builder().build().unwrap();
        let req = client
            .get(
                "http://host.com?s=abc&b=>3b=!3&c=%2&c=%3&c=<1&imagemogr2/=1&watermark/h=3&a=1&a=2&a=3",
            )
            .build()
            .unwrap();
        let query = req.url().query().unwrap();
        println!("query string: {}", urlencoding::encode(query));
        println!("query string: {}", query);
        // assert_eq!(
        //     "a=1&a=2&a=3&b=%3E3&c=%3C1&imagemogr2%2F=1&s=abc&watermark%2Fh=3",
        //     query
        // );
        let parse = req.url().query_pairs();
        for (k, v) in parse {
            println!("{} -> {}", k, v);
        }
        // let _a = client.execute(request).await.unwrap();
    }

    #[test]
    fn test_gen_format_headers() {
        let expect_headers = "access-control-request-method=get&access-control-request-method=put&host=www.baidu.com&x-cos-custom=a&x-cos-custom=b&x-cos-custom=c";
        let expect_header_list = [
            "access-control-request-method",
            "access-control-request-method",
            "host",
            "x-cos-custom",
            "x-cos-custom",
            "x-cos-custom",
        ];
        let mut header = HeaderMap::new();
        header.append("Host", HeaderValue::from_static("www.baidu.com"));
        header.append(
            "access-control-request-method",
            HeaderValue::from_static("get"),
        );
        header.append(
            "access-control-request-method",
            HeaderValue::from_static("put"),
        );
        header.append("x-cos-custom", HeaderValue::from_static("a"));
        header.append("x-cos-custom", HeaderValue::from_static("b"));
        header.append("x-cos-custom", HeaderValue::from_static("c"));
        header.append("should-be-remove", HeaderValue::from_static("value"));
        let (headers, header_list) = AuthorizationComputer::gen_format_headers(&header).unwrap();
        assert_eq!(headers, expect_headers);
        assert_eq!(header_list, expect_header_list);
    }

    #[tokio::test]
    async fn test_gen_format_parameters() {
        let client = reqwest::Client::builder().build().unwrap();
        let req = client
            .get(
                "http://host.com?s=abc&b=>3b=!3&c=%2&c=%3&c=<1&imagemogr2/=1&watermark/h=3&a=1&a=2&a=3",
            )
            .build()
            .unwrap();
        let parse = req.url().query_pairs();

        let (format_paramter, signed_paramter_list) =
            AuthorizationComputer::gen_format_parameters(parse).unwrap();
        assert_eq!(format_paramter, "a=1&a=2&a=3&b=%3E3b%3D%213&c=%3C1&s=abc");
        assert_eq!(signed_paramter_list, vec!["a", "a", "a", "b", "c", "s"]);
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("host!=host"), "host%21%3Dhost");
        assert_eq!(urlencoding::encode("host'=host"), "host%27%3Dhost");
        assert_eq!(urlencoding::encode("host(=host"), "host%28%3Dhost");
        assert_eq!(urlencoding::encode("host)=host"), "host%29%3Dhost");
        assert_eq!(urlencoding::encode("host*=host"), "host%2A%3Dhost");
    }

    #[test]
    fn test_new_authorization() {
        let expect_authorization = "q-sign-algorithm=sha1&q-ak=QmFzZTY0IGlzIGEgZ2VuZXJp&q-sign-time=1480932292;1481012292&q-key-time=1480932292;1481012292&q-header-list=host;x-cos-content-sha1;x-cos-stroage-class&q-url-param-list=&q-signature=ce4ac0ecbcdb30538b3fee0a97cc6389694ce53a";
        let secret_id = "QmFzZTY0IGlzIGEgZ2VuZXJp";
        let secret_key = "AKIDZfbOA78asKUYBcXFrJD0a1ICvR98JM";
        let host = "testbucket-125000000.cos.ap-guangzhou.myqcloud.com";
        let uri = "http://testbucket-125000000.cos.ap-guangzhou.myqcloud.com/testfile2";
        let client = reqwest::Client::builder().build().unwrap();
        let req = client.get(uri).build().unwrap();
        let parse = req.url().query_pairs();
        let start_time = 1480932292;
        let end_time = 1481012292;
        let mut headers = HeaderMap::new();
        headers.insert("Host", HeaderValue::from_str(host).unwrap());
        headers.insert(
            "x-cos-content-sha1",
            HeaderValue::from_static("db8ac1c259eb89d4a131b253bacfca5f319d54f2"),
        );
        headers.insert("x-cos-stroage-class", HeaderValue::from_static("nearline"));
        let auth_time = AuthTime::new(start_time, end_time - start_time);
        let actual = AuthorizationComputer::authorazation(
            &secret_id,
            &secret_key,
            &uri,
            auth_time,
            &headers,
            parse,
        )
        .unwrap();

        assert_eq!(expect_authorization, actual);
    }
}
