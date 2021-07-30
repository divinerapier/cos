use super::authenticator;
use super::authenticator::AuthTime;
use anyhow::Result;
use form_urlencoded::Parse;
use hyper::{
    header::{HeaderValue, AUTHORIZATION},
    HeaderMap, StatusCode,
};
use reqwest::Body;
use std::sync::Arc;

pub struct Client {
    inner: Arc<ClientImpl>,
}

pub(crate) struct ClientImpl {
    access_key: String,
    secret_key: String,

    bucket_url: url::Url,

    inner: reqwest::Client,
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
        authenticator::authorazation(ak, sk, method, uri, auth_time, headers, queries).unwrap()
    }

    pub async fn get(&self, url: &str, path: &str) -> Result<reqwest::Response> {
        let now = chrono::Local::now().timestamp();
        let expire = 180 * 24 * 3600;
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
        key: &str,
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
        log::debug!("put url: {}", url);
        let url = url::Url::parse(url)?;
        let builder = self.inner.put(url).body(body);
        let mut request = builder.build()?;
        let queries = request.url().query_pairs();
        let auth = self.auth(now, expire, "put", key, request.headers(), queries);

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

        let bucket_url = url::Url::parse(&bucket_url)?;

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
    pub async fn get(&self, key: &str) -> Result<String, String> {
        let client = &self.client;
        let mut url = client.bucket_url.clone();
        url.set_path(&crate::urlencoding::encode_uri_component(key, None));
        log::debug!("url: {}", url);
        log::debug!("url: {}", url);
        let response = client
            .get(url.as_str(), &["/", key].concat())
            .await
            .unwrap();
        log::debug!("response header: {:?}", response.headers());
        let status_code = response.status();
        let text = response.text().await.unwrap();
        log::debug!("text: {}", text);
        if status_code >= StatusCode::from_u16(300).unwrap() {
            Err(text)
        } else {
            Ok(text)
        }
    }

    pub async fn put<T: Into<Body> + AsRef<[u8]>>(
        &self,
        key: &str,
        body: T,
    ) -> Result<String, String> {
        let client = &self.client;
        let mut url = client.bucket_url.clone();
        url.set_path(&crate::urlencoding::encode_uri_component(key, None));
        log::debug!("url: {}", url);
        let response = client
            .put(url.as_str(), &["/", key].concat(), body)
            .await
            .unwrap();
        log::debug!("response header: {:?}", response.headers());
        let status_code = response.status();
        let text = response.text().await.unwrap();
        log::debug!("text: {}", text);
        if status_code >= StatusCode::from_u16(300).unwrap() {
            Err(text)
        } else {
            Ok(text)
        }
    }

    pub async fn upload(&self, key: &str, filepath: &str) {}

    async fn get_resumable_upload_id(&self, name: &str) -> Result<String> {
        Ok("".to_string())
    }

    async fn list_uploads(&self, opt: &ObjectListUPloadsOptions) {}
}

pub struct ObjectListUPloadsOptions {
    delimiter: Option<String>,
    encoding_type: Option<String>,
    prefix: Option<String>,
    max_uploads: Option<u64>,
    key_maker: Option<String>,
    uploadid_maker: Option<String>,
}

impl ObjectListUPloadsOptions {
    fn to_query(&self) -> Option<String> {
        let mut queries = Vec::with_capacity(6);
        if let Some(delimiter) = self.delimiter.as_ref() {
            queries.push(["Delimiter=", delimiter].concat());
        }
        if let Some(encoding_type) = self.delimiter.as_ref() {
            queries.push(["EncodingType=", encoding_type].concat());
        }
        if let Some(prefix) = self.prefix.as_ref() {
            queries.push(["Prefix=", prefix].concat());
        }
        if let Some(max_uploads) = self.max_uploads.as_ref() {
            queries.push(format!("MaxUploads={}", max_uploads));
        }
        if let Some(key_maker) = self.key_maker.as_ref() {
            queries.push(["KeyMarker=", key_maker].concat());
        }
        if let Some(uploadid_maker) = self.uploadid_maker.as_ref() {
            queries.push(["UploadIDMarker=", uploadid_maker].concat());
        }
        if queries.is_empty() {
            None
        } else {
            Some(queries.join("&"))
        }
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
    use hyper::http::uri;

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
            log::debug!("{}", result);
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
        // log::debug!("{}", ecma.checksum(b"hello world"));
        // log::debug!("{}", ecma.checksum(b"hello world"));
        // log::debug!("{}", ecma.checksum(b"hello world"));
        // log::debug!("{}", ecma.checksum(b"hello world"));
        log::debug!("{}", crc64::crc64(0, b"hello world"));
    }

    #[test]
    fn test_http_header() {
        let mut header = HeaderMap::new();
        header.append("key0", HeaderValue::from_static("val0-0"));
        header.append("key0", HeaderValue::from_static("val0-1"));
        header.append("key0", HeaderValue::from_static("val0-2"));

        for (key, values) in header.iter() {
            log::debug!("key: {:?}  values: {:?}", key, values);
        }

        log::debug!("{:?}", header);
        // log::debug!("{:?}", header.get("key0").as_ref().unwrap());
        log::debug!("{:?}", header.get_all("key0"));
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
        log::debug!("query string: {}", urlencoding::encode(query));
        log::debug!("query string: {}", query);
        // assert_eq!(
        //     "a=1&a=2&a=3&b=%3E3&c=%3C1&imagemogr2%2F=1&s=abc&watermark%2Fh=3",
        //     query
        // );
        let parse = req.url().query_pairs();
        for (k, v) in parse {
            log::debug!("{} -> {}", k, v);
        }
        // let _a = client.execute(request).await.unwrap();
    }

    #[test]
    fn test_url() {
        let cases = vec![
            (
                "http://example.org/acoustics.html",
                "http",
                "example.org",
                "/acoustics.html",
                "",
                "",
                "http://example.org/acoustics.html",
            ),
            (
                "https://bomb.example.org/",
                "https",
                "bomb.example.org",
                "/",
                "",
                "",
                "https://bomb.example.org/",
            ),
            (
                "http://www.example.org/board/ball.html",
                "http",
                "www.example.org",
                "/board/ball.html",
                "",
                "",
                "http://www.example.org/board/ball.html",
            ),
            (
                "http://example.com/achiever.php",
                "http",
                "example.com",
                "/achiever.php",
                "",
                "",
                "http://example.com/achiever.php",
            ),
            (
                "http://www.example.com/birds.aspx#bee",
                "http",
                "www.example.com",
                "/birds.aspx",
                "",
                "bee",
                "http://www.example.com/birds.aspx#bee",
            ),
            (
                "http://www.example.com/?basketball=arithmetic&base=baby",
                "http",
                "www.example.com",
                "/",
                "basketball=arithmetic&base=baby",
                "",
                "http://www.example.com/?basketball=arithmetic&base=baby",
            ),
            (
                "http://www.example.net/?border=bell&aunt=bath",
                "http",
                "www.example.net",
                "/",
                "border=bell&aunt=bath",
                "",
                "http://www.example.net/?border=bell&aunt=bath",
            ),
            (
                "https://www.example.com/",
                "https",
                "www.example.com",
                "/",
                "",
                "",
                "https://www.example.com/",
            ),
            (
                "https://appliance.example.com/#bait",
                "https",
                "appliance.example.com",
                "/",
                "",
                "bait",
                "https://appliance.example.com/#bait",
            ),
            (
                "https://boundary.example.com/",
                "https",
                "boundary.example.com",
                "/",
                "",
                "",
                "https://boundary.example.com/",
            ),
            (
                "http://www.example.org/air/army.html#airplane",
                "http",
                "www.example.org",
                "/air/army.html",
                "",
                "airplane",
                "http://www.example.org/air/army.html#airplane",
            ),
            (
                "https://battle.example.net/border",
                "https",
                "battle.example.net",
                "/border",
                "",
                "",
                "https://battle.example.net/border",
            ),
            (
                "http://bells.example.net/afterthought#battle",
                "http",
                "bells.example.net",
                "/afterthought",
                "",
                "battle",
                "http://bells.example.net/afterthought#battle",
            ),
            (
                "http://www.example.com/?aunt=border&beds=advice",
                "http",
                "www.example.com",
                "/",
                "aunt=border&beds=advice",
                "",
                "http://www.example.com/?aunt=border&beds=advice",
            ),
            (
                "http://www.example.com/birds",
                "http",
                "www.example.com",
                "/birds",
                "",
                "",
                "http://www.example.com/birds",
            ),
            (
                "http://example.com/believe/berry",
                "http",
                "example.com",
                "/believe/berry",
                "",
                "",
                "http://example.com/believe/berry",
            ),
            (
                "http://www.example.com/bell?basketball=apparatus",
                "http",
                "www.example.com",
                "/bell",
                "basketball=apparatus",
                "",
                "http://www.example.com/bell?basketball=apparatus",
            ),
            (
                "http://www.example.com/",
                "http",
                "www.example.com",
                "/",
                "",
                "",
                "http://www.example.com/",
            ),
            (
                "http://www.example.com/bedroom",
                "http",
                "www.example.com",
                "/bedroom",
                "",
                "",
                "http://www.example.com/bedroom",
            ),
            (
                "https://www.example.com/?balance=bike&afterthought=activity",
                "https",
                "www.example.com",
                "/",
                "balance=bike&afterthought=activity",
                "",
                "https://www.example.com/?balance=bike&afterthought=activity",
            ),
            (
                "https://www.example.com/balance/airport.php",
                "https",
                "www.example.com",
                "/balance/airport.php",
                "",
                "",
                "https://www.example.com/balance/airport.php",
            ),
            (
                "https://example.com/battle",
                "https",
                "example.com",
                "/battle",
                "",
                "",
                "https://example.com/battle",
            ),
            (
                "http://www.example.com/",
                "http",
                "www.example.com",
                "/",
                "",
                "",
                "http://www.example.com/",
            ),
            (
                "http://www.example.com/#authority",
                "http",
                "www.example.com",
                "/",
                "",
                "authority",
                "http://www.example.com/#authority",
            ),
        ];

        for (origin_url, schema, host, path, raw_query, fragment, value) in cases {
            let u = url::Url::parse(origin_url).unwrap();
            assert_eq!(u.scheme(), schema);
            assert_eq!(u.host_str().unwrap(), host);
            assert_eq!(u.path(), path);
            assert_eq!(u.query().unwrap_or(""), raw_query);
            assert_eq!(u.fragment().unwrap_or(""), fragment);
            assert_eq!(u.as_str(), value);
        }
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
        log::debug!("method: {}", req.method().as_str().to_lowercase());
        let auth_time = AuthTime::new(start_time, end_time - start_time);
        let actual = authenticator::authorazation(
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

    async fn client() -> Client {
        Builder::new()
            .set_access_key("")
            .set_secret_key("")
            .set_region("")
            .set_bucket("")
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_get_object() {
        let client = client().await;
        let text = client.object().get("path/1/8.txt").await.unwrap();
        assert_eq!("hello world", text);
    }

    #[tokio::test]
    async fn test_get_object2() {
        let client = client().await;

        let text = client.object().get("path/1/%9.txt").await.unwrap();
        assert_eq!("hello world", text);
    }

    #[tokio::test]
    async fn test_get_object3() {
        let client = client().await;

        let text = client.object().get("path/1/%19.txt").await.unwrap();
        assert_eq!("hello world", text);
    }

    #[tokio::test]
    async fn test_put_object() {
        let client = client().await;

        let _text = client
            .object()
            .put("path/1/8.txt", "hello world")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_put_object2() {
        let client = client().await;

        let _text = client
            .object()
            .put("path/1/%9.txt", "hello world")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_put_object3() {
        let client = client().await;

        let _text = client
            .object()
            .put("path/1/%19.txt", "hello world")
            .await
            .unwrap();
    }
}
