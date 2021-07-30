use anyhow::Result;
use form_urlencoded::Parse;
use hyper::HeaderMap;
use std::collections::HashMap;

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

#[derive(Debug)]
pub(crate) struct AuthTime {
    sign_start_time: i64,
    sign_end_time: i64,
    key_start_time: i64,
    key_end_time: i64,
}

impl AuthTime {
    pub(crate) fn new(start_timestamp: i64, expire_in_secret: i64) -> AuthTime {
        AuthTime {
            sign_start_time: start_timestamp,
            sign_end_time: start_timestamp + expire_in_secret,
            key_start_time: start_timestamp,
            key_end_time: start_timestamp + expire_in_secret,
        }
    }

    pub(crate) fn sign(&self) -> String {
        format!("{};{}", self.sign_start_time, self.sign_end_time)
    }

    pub(crate) fn key(&self) -> String {
        format!("{};{}", self.key_start_time, self.key_end_time)
    }
}

pub(crate) fn authorazation(
    secret_id: &str,
    secret_key: &str,
    method: &str,
    path: &str,
    auth_time: AuthTime,
    headers: &HeaderMap,
    queries: Parse,
) -> Result<String> {
    log::debug!("authorazation.");
    log::debug!("secret_id: {}", secret_id);
    log::debug!("secret_key: {}", secret_key);
    log::debug!("method: {}", method);
    log::debug!("path: {}", path);
    log::debug!("auth_time: {:?}", auth_time);
    log::debug!("headers: ");
    for (k, v) in headers.iter() {
        log::debug!("\t{}: {:?}", k, v);
    }
    log::debug!("queries: ");
    for (k, v) in queries {
        log::debug!("\t{}: {}", k, v);
    }
    let sign_time = auth_time.sign();
    let key_time = auth_time.key();
    let sign_key = calc_sign_key(secret_key, &key_time);
    let (format_headers, signed_header_list) = gen_format_headers(headers)?;
    let (format_parameters, signed_parameter_list) = gen_format_parameters(queries)?;
    log::debug!("path: {}", path);
    let format_string = format!(
        "{}\n{}\n{}\n{}\n",
        method, path, &format_parameters, &format_headers
    );
    let string_to_sign = cal_string_to_sign("sha1", &key_time, &format_string);
    let signature = cal_signature(sign_key.as_bytes(), string_to_sign.as_bytes());

    log::debug!("format_string: {}", format_string);
    log::debug!("string_to_sign: {}", string_to_sign);
    log::debug!("secret_id: {}", secret_id);
    log::debug!("sign_time: {}", sign_time);
    log::debug!("key_time: {}", key_time);
    log::debug!("signed_header_list: {}", signed_header_list.join(";"));
    log::debug!("signed_parameter_list: {}", signed_parameter_list.join(";"));
    log::debug!("signature: {}", signature);

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
    sha1.update(format_string.as_bytes());
    let result = sha1.finish();
    format!("{}\n{}\n{}\n", alg, sign_time, hex::encode(&result))
}

fn cal_signature(sign_key: &[u8], string_to_sign: &[u8]) -> String {
    log::debug!(
        "cal signature:\nkey: {}\nvalue: {}\n",
        unsafe { String::from_utf8_unchecked(Vec::from(sign_key)) },
        unsafe { String::from_utf8_unchecked(Vec::from(string_to_sign)) },
    );
    let result = hmacsha1::hmac_sha1(sign_key, string_to_sign);
    log::debug!("digest: {:?}\n\n", result);
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
    if !ishex(s.chars().nth(index + 1).unwrap()) {
        return false;
    }
    if ishex(s.chars().nth(index + 1).unwrap()) {
        return false;
    }
    let s = &s[index + 2..];
    s.is_empty() || is_valid_query(s)
}

fn gen_format_headers(headers: &HeaderMap) -> Result<(String, Vec<String>)> {
    let mut keys = vec![];
    let mut kv_pairs = HashMap::new();
    let mut header_list = vec![];
    for (key, values) in headers.iter() {
        let key = key.as_str().to_lowercase();
        if !is_sign_header(&key) {
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
        if !is_valid_query(values.as_ref()) {
            continue;
        }
        if is_ci_parameter(&key) {
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
    SIGN_HEADERS.contains_key(name) || name.starts_with("x-cos-")
}

#[cfg(test)]
mod test {
    use hyper::header::HeaderValue;

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
            let result = calc_sign_key(case.0, case.1);
            assert_eq!(case.2, &result);
        }
    }

    #[test]
    fn test_hex() {
        for c in '0'..='9' {
            assert!(ishex(c));
        }
        for c in 'A'..='F' {
            assert!(ishex(c));
        }
        for c in 'a'..='f' {
            assert!(ishex(c));
        }

        assert!(!ishex('!'));
        assert!(!ishex('%'));
        assert!(!ishex('g'));
        assert!(!ishex('G'));
        assert!(!ishex('z'));
        assert!(!ishex('Z'));
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
        let (headers, header_list) = gen_format_headers(&header).unwrap();
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

        let (format_paramter, signed_paramter_list) = gen_format_parameters(parse).unwrap();
        assert_eq!(format_paramter, "a=1&a=2&a=3&b=%3E3b%3D%213&c=%3C1&s=abc");
        assert_eq!(signed_paramter_list, vec!["a", "a", "a", "b", "c", "s"]);
    }
}
