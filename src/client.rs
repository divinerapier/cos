use std::{collections::HashMap, sync::Arc};

use form_urlencoded::Parse;
use hyper::{
    header::{HeaderValue, AUTHORIZATION},
    HeaderMap,
};
use reqwest::Body;

use anyhow::Result;

lazy_static::lazy_static! {
    static ref SIGN_HEADERS: HashMap< &'static str, bool> = {
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
        m
    };
}

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
        method: &str,
        path: &str,
        auth_time: AuthTime,
        headers: &HeaderMap,
        queries: Parse,
    ) -> Result<String> {
        let sign_time = auth_time.sign();
        let key_time = auth_time.key();
        let sign_key = Self::calc_sign_key(secret_key, &key_time);
        let (format_headers, signed_header_list) = Self::gen_format_headers(headers)?;
        let (format_parameters, signed_parameter_list) = Self::gen_format_parameters(queries)?;
        let format_string = format!(
            "{}\n{}\n{}\n{}\n",
            method, path, &format_parameters, &format_headers
        );
        let string_to_sign = Self::cal_string_to_sign("sha1", &key_time, &format_string);
        let signature = Self::cal_signature(sign_key.as_bytes(), string_to_sign.as_bytes());

        println!("format_string: {}", format_string);
        println!("string_to_sign: {}", string_to_sign);

        println!("secret_id: {}", secret_id);
        println!("sign_time: {}", sign_time);
        println!("key_time: {}", key_time);
        println!("signed_header_list: {}", signed_header_list.join(";"));
        println!("signed_parameter_list: {}", signed_parameter_list.join(";"));
        println!("signature: {}", signature);

        let auth = [
            format!("q-sign-algorithm={}", "sha1"),
            format!("q-ak={}", secret_id),
            format!("q-sign-time={}", sign_time),
            format!("q-key-time={}", key_time),
            format!("q-header-list={}", signed_header_list.join(";")),
            format!("q-url-param-list={}", signed_parameter_list.join(";")),
            format!("q-signature={}", signature),
        ]
        .join("&");

        Ok(auth)
    }

    fn cal_string_to_sign(alg: &str, sign_time: &str, format_string: &str) -> String {
        let mut sha1 = openssl::sha::Sha1::new();
        sha1.update(&format_string.as_bytes());
        let result = sha1.finish();
        format!("{}\n{}\n{}\n", alg, sign_time, hex::encode(&result))
    }

    fn cal_signature(sign_key: &[u8], string_to_sign: &[u8]) -> String {
        println!(
            "cal signature:\nkey: {}\nvalue: {}\n",
            unsafe { String::from_utf8_unchecked(Vec::from(sign_key)) },
            unsafe { String::from_utf8_unchecked(Vec::from(string_to_sign)) },
        );
        let result = hmacsha1::hmac_sha1(sign_key, string_to_sign);
        println!("digest: {:?}\n\n", result);
        hex::encode(&result)
    }

    fn calc_sign_key(sk: &str, key_time: &str) -> String {
        let result = hmacsha1::hmac_sha1(sk.as_bytes(), key_time.as_bytes());
        hex::encode(result)
    }

    fn ishex(c: char) -> bool {
        matches!(c, '0'..='9'|'a'..='f'|'A'..='F')
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
        method: &str,
        uri: &str,
        headers: &HeaderMap,
        queries: Parse,
    ) -> String {
        let ak = &self.access_key;
        let sk = &self.secret_key;

        let auth_time = AuthTime::new(begin_timestamp, expire_in_second);

        AuthorizationComputer::authorazation(ak, sk, method, uri, auth_time, headers, queries)
            .unwrap()
    }

    pub async fn get(&self, url: &str, path: &str) -> Result<reqwest::Response> {
        let now = chrono::Local::now().timestamp();
        let expire = 180 * 24 * 3600;
        // let url_str = url.as_str().to_string();
        let builder = self.inner.get(url);
        let mut request = builder.build()?;
        let queries = request.url().query_pairs();
        let auth = self.auth(now, expire, "get", path, request.headers(), queries);
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_str(&auth)?);
        Ok(self.inner.execute(request).await?)
    }

    pub async fn put<T: Into<Body> + AsRef<[u8]>>(
        &self,
        url: &str,
        path: &str,
        body: T,
    ) -> Result<reqwest::Response> {
        let now = chrono::Local::now().timestamp();
        let expire = 180 * 24 * 3600;
        let content_md5 = {
            use openssl::hash::{Hasher, MessageDigest};
            let mut h = Hasher::new(MessageDigest::md5()).unwrap();
            h.update(body.as_ref()).unwrap();
            h.finish().unwrap()
        };
        let builder = self.inner.put(url).body(body);
        let mut request = builder.build()?;
        let queries = request.url().query_pairs();
        let auth = self.auth(now, expire, "put", path, request.headers(), queries);

        request.headers_mut().insert(
            "x-cos-meta-md5",
            HeaderValue::from_str(&hex::encode(content_md5))?,
        );
        request.headers_mut().insert(
            "Content-MD5",
            HeaderValue::from_str(&base64::encode(content_md5))?,
        );
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_str(&auth)?);
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

    pub fn object(&self) -> ObjectService {
        ObjectService {
            client: self.inner.clone(),
        }
    }
}

pub struct ObjectService {
    client: Arc<ClientImpl>,
}

impl ObjectService {
    pub async fn get(&self, key: &str) -> String {
        let client = &self.client;
        let url = format!(
            "{}/{}",
            client.bucket_url,
            crate::urlencoding::encode_uri_component(key, None)
        );
        println!("url: {}", url);
        let response = client.get(&url, &["/", key].concat()).await.unwrap();
        let text = response.text().await.unwrap();
        println!("text: {}", text);
        text
    }

    pub async fn put<T: Into<Body> + AsRef<[u8]>>(&self, key: &str, body: T) -> String {
        let client = &self.client;
        let url = format!(
            "{}/{}",
            client.bucket_url,
            crate::urlencoding::encode_uri_component(key, None)
        );
        println!("url: {}", url);
        let response = client.put(&url, &["/", key].concat(), body).await.unwrap();
        println!("response header: {:?}", response.headers());
        let text = response.text().await.unwrap();
        println!("text: {}", text);
        text
    }
}

pub struct BucketService {
    client: Arc<ClientImpl>,
}

// pub struct BucketGetOptions {
//     prefix: String,
//     delimiter: String,
//     encoding_type: String,
//     marker: String,
//     max_keys: String,
// }

impl BucketService {
    pub async fn get(&self) -> reqwest::Response {
        let client = self.client.clone();
        let builder = client.inner.get("https://www.baidu.com");
        let request = builder.build().unwrap();
        client.inner.execute(request).await.unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_md5() {
        use openssl::hash::{Hasher, MessageDigest};
        let cases: Vec<(&str, &str)> = vec![
            (
                "AJ37vFp7YflTu5cPRPBJCkE4qStC5XBgCF1AqKVJqy6yI5GVlyPL55FFYpgLn8Lx",
                "ac4dc71459982db5d8521f704615bc35",
            ),
            (
                "CLiEtMFnqWQU3Iu7vsQJnJ5fMyRVlF6yMT1uoAJmvWOGloP/VImagaFDOboHm+Dg",
                "fe770a7a9c74bb6505692f441298b8c2",
            ),
            (
                "Pg7tJEhvnXWecNezz8Gow4hYiVCid84+WClek/MgNGA/S32eduW4s45hn5UWxO1n",
                "b751654beea40f935f8cac6dd468e0fc",
            ),
            (
                "TH8TUzrt3RdpfxprKm3/HTqx05sbIZE0Yklsaqu+EluNkDZD4xjfgFr2Bvyg5r27",
                "de54d414abb864ccb9ca32ff0505e55e",
            ),
            (
                "vYa9xK+fuqof0T6aN0iQIHANBZy/hH9UiW2LD36fmW0c3IHhv3bBHuRxRDYBdgD1",
                "705cd6de2a3b803dcc3d94ee5eb15b43",
            ),
            (
                "4qCgl+6/+hUTzxmoS2frIBW9V5P54vARKwhO12HIpu2eP9Xk04zXUkyddLMLICvu",
                "a75d69c6fbafe228360c6479bab7c2ed",
            ),
            (
                "eqbhHzsVduc0cALT5pSOLfrxeDg0HOUbuyFnyoX7fYf/tFpOs8vBSj7UrLFxtQza",
                "3aeb99396244c17b2e7dcee7be946cb7",
            ),
            (
                "aT9MuXWmzzeZGGw/p3Y4WHthJMoQ0S1N+vBBXyteF+RJTwFBE1b/oG+fqHCCNe15",
                "f0c401d1151fadec2d6dbf1bb8191ca7",
            ),
            (
                "tfkIR1MsZ/fh+wb02IqBUpSXWx9WrUxr967inu3GZCJLNn9kqgrej484qpfp3xSr",
                "5139c0d4799a848e11cfdcd07a112cee",
            ),
            (
                "doT2cHiLeEQJ4ray3RLPQHsjAS2LRgREou/OTZI7YrQi0zg1jp53bg2jrDxK6ult",
                "b516229701ecfdba5f6da6cb57275824",
            ),
            (
                "U74cPGrFg8ybDHxxDCiDOv8kjBtIUe2Pr/u3v802qdzlce9sV79iAHU1K4uK7MWO",
                "fc6419e8fbae233613c530a8a6330adb",
            ),
            (
                "/WDnZNu/Qzu7xEMMAgH7f9QkEy0cUKrwUrxXeAezpxkU+hI2ZfCbTs81vdRIA54l",
                "05c0bd010f635578d81030dc9d48515b",
            ),
            (
                "rTkjsuOHXVMAYqVwiT3halOsn+UfU02LsidNAXXLBmWO/aMcSVvBAya/hLSh2CPe",
                "883a46be6affff4c5a26504aa4a5e0ae",
            ),
            (
                "Pwg3l1KFjbsoprmi5cl3+I/iCUh6SuXGym1Mjlz/c5yQK/0AquuC2mKdRJ25ce+z",
                "713dcb88f00ebb5e803b6ff26c5e4e41",
            ),
            (
                "c7yym/+Q8iwWGrU60+AgpaB5FzgonWQ7OCAmtI8ZELouXdiEXu/85AxEL7oRmXE/",
                "5349c89aa7986138fb26a46f4cf0c77a",
            ),
            (
                "v7ZsO1spbsy0jkUPEFpRCnootE3XB/raX1wYBCaWJWGEvXws16lxV7iq+FPYs0pU",
                "63d371f791642965d08fd8423890b1f9",
            ),
        ];
        let mut h = Hasher::new(MessageDigest::md5()).unwrap();
        for case in cases {
            h.update(case.0.as_bytes()).unwrap();
            let result = hex::encode(h.finish().unwrap());
            println!("{}", result);
            assert_eq!(result, case.1);
        }
    }

    #[test]
    fn test_crc64() {
        let _ecma: crc::Crc<_> = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182);
        let _cases: Vec<(&str, u64)> = vec![
            ("hello world", 5981764153023615706),
            (
                "6u+xqlgzGU6innFnMLDkgH114ONmkLSSbKA3DFZwPuyyQmuvVikXefCulnAAIqw2",
                14572412854704403212,
            ),
            (
                "oY0EroZoA4BMKDX+g4Dl5mYxT/vI37kIZ7gG2dmSPNgzk7kKvY/cFm+Suw+3/cCc",
                5164735488784417736,
            ),
            (
                "Y/SaFhKcxFHtl1V+aPraQPJaHDBlbOqScYtM++Ax8Hmw2VSrAl5rXvk27bd97md7",
                17244667989215551457,
            ),
            (
                "2tA/hj2iiS8FnU2cHangy02TKAEl+W74fSmOCjUwTcax+L9jr6+F94N/E9GfDIkb",
                18004985755321710523,
            ),
            (
                "JEke7ovDJBOX47XJQtKBDLQ9GRem5yUc5c27w1baK4mPKm0IlB8WUbZcuymD4lzY",
                10017151388654735929,
            ),
            (
                "YxSfuCzNyHv7sWlSUwP4114QcEYMAn4YbogHvMGpyTjHIkrWZd87yPx91vaduSMo",
                15132840424691900123,
            ),
            (
                "G80JZKRIqJZC3J7kkMp68BQZ8cxY/GxffWc44yg+mMFHhe8va5BVuRE7Lv06zQTg",
                6198368208398009937,
            ),
            (
                "lMm/+eTp+m00iC0Z7kt1SY5TCps6ASmUWCyJMRvxm/Wnn0jNHSxh/5aSz+StTrmD",
                13093119539118966429,
            ),
            (
                "wqYVg80ziXeFrq0iFtAW/i0a+rXhipRVaj57GIPIcXvlkcbIJDDaSU+4L4Etknem",
                14019831132253083013,
            ),
            (
                "effPLl5tyQgPgK5rTlRLlDIuajWm75CKF8HF7V3It8Qh2ic+YNgkj6WyytTXRAK3",
                11901856423799743978,
            ),
            (
                "6x0ahIlUs25TulQY/BweZX8CXISYLqapGIpYPOMkk1GsA0bz2M5W3ZNh0uUQldJn",
                7240874481603246853,
            ),
            (
                "llxCS2HZzvcxLcJIxeNiAmlIuHrci4F3KnDgWg0maftDBdGZgpmjdSDwitS8xXBg",
                5112180515127266155,
            ),
            (
                "u1a1usGI5bhXd8UApjtXKYhWdv3XOMwxf/AvuV14dZoYNFCTBsjqiOb6w+wS3rEg",
                8991569294952157660,
            ),
            (
                "RVKFutUYf/Lmyf9GIdaE23UbAO27rL92Uk5mZiM96BHAddhpK/TRqY4xHwZYrq0a",
                6744385118952109351,
            ),
            (
                "uj0InFhZN75mRsZc3upNb6N0iRDQqXDQkvlOFDRpCn8iFyHJJrNSTMyOAw+HFCrZ",
                18286972960748437890,
            ),
            (
                "FiF4FTN8BG7zxUf9nOVwIEoX4HdtnfsctkHOIvWOmOkccqQjDt47g9am1nBEuL2v",
                15436735472894984101,
            ),
        ];
        // for case in cases {
        //     let mut digest = ecma.digest();
        //     digest.update(case.0.as_bytes());
        //     // assert_eq!(digest.finalize(), case.1);
        // }
        // println!("{}", ecma.checksum(b"hello world"));
        // println!("{}", ecma.checksum(b"hello world"));
        // println!("{}", ecma.checksum(b"hello world"));
        // println!("{}", ecma.checksum(b"hello world"));
        println!("{}", crc64::crc64(0, b"hello world"));
    }

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
    fn test_hex() {
        for c in '0'..='9' {
            assert!(AuthorizationComputer::ishex(c));
        }
        for c in 'A'..='F' {
            assert!(AuthorizationComputer::ishex(c));
        }
        for c in 'a'..='f' {
            assert!(AuthorizationComputer::ishex(c));
        }

        assert!(!AuthorizationComputer::ishex('!'));
        assert!(!AuthorizationComputer::ishex('%'));
        assert!(!AuthorizationComputer::ishex('g'));
        assert!(!AuthorizationComputer::ishex('G'));
        assert!(!AuthorizationComputer::ishex('z'));
        assert!(!AuthorizationComputer::ishex('Z'));
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
        let req = client.put(uri).build().unwrap();
        let parse = req.url().query_pairs();
        let start_time = 1480932292;
        let end_time = 1481012292;
        let path = req.url().path();
        let mut headers = HeaderMap::new();
        headers.insert("Host", HeaderValue::from_str(host).unwrap());
        headers.insert(
            "x-cos-content-sha1",
            HeaderValue::from_static("db8ac1c259eb89d4a131b253bacfca5f319d54f2"),
        );
        headers.insert("x-cos-stroage-class", HeaderValue::from_static("nearline"));
        println!("method: {}", req.method().as_str().to_lowercase());
        let auth_time = AuthTime::new(start_time, end_time - start_time);
        let actual = AuthorizationComputer::authorazation(
            &secret_id,
            &secret_key,
            &req.method().as_str().to_lowercase(),
            &path,
            auth_time,
            &headers,
            parse,
        )
        .unwrap();

        assert_eq!(expect_authorization, actual);
    }

    #[tokio::test]
    async fn test_get_object() {
        let client = Builder::new()
            .set_access_key("")
            .set_secret_key("")
            .set_region("")
            .set_bucket("")
            .build()
            .unwrap();

        let text = client.object().get("path1/1.txt").await;
        assert_eq!("sdasd", text);
    }

    #[tokio::test]
    async fn test_put_object() {
        let client = Builder::new()
            .set_access_key("")
            .set_secret_key("")
            .set_region("")
            .set_bucket("")
            .build()
            .unwrap();

        let _text = client.object().put("path/1/6.txt", "hello world").await;
    }
}
