//! Minimal S3-compatible client (AWS S3, Cloudflare R2, Backblaze B2, MinIO, Wasabi) using
//! presigned URLs from `rusty-s3` and streaming uploads/downloads with `reqwest`.

use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
}

impl S3Config {
    pub fn validate(&self) -> Result<(), String> {
        let url = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| "Endpoint must be a URL like https://s3.eu-central-1.amazonaws.com".to_string())?;
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err("Endpoint must start with https:// (or http:// for a server on the same network)".into());
        }
        if self.bucket.is_empty()
            || self.bucket.len() > 63
            || !self
                .bucket
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        {
            return Err("Invalid bucket name".into());
        }
        if self.access_key.is_empty() || self.secret_key.is_empty() {
            return Err("Access key and secret key are required".into());
        }
        if self.prefix.contains("..") || self.prefix.len() > 200 {
            return Err("Invalid prefix".into());
        }
        Ok(())
    }

    pub fn key(&self, name: &str) -> String {
        let p = self.prefix.trim_matches('/');
        if p.is_empty() {
            name.to_string()
        } else {
            format!("{p}/{name}")
        }
    }

    fn bucket(&self) -> Result<(Bucket, Credentials), String> {
        let url = reqwest::Url::parse(&self.endpoint).map_err(|e| e.to_string())?;
        let style = if self.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        let region = if self.region.is_empty() {
            "us-east-1".to_string()
        } else {
            self.region.clone()
        };
        let bucket = Bucket::new(url, style, self.bucket.clone(), region).map_err(|e| e.to_string())?;
        Ok((
            bucket,
            Credentials::new(self.access_key.clone(), self.secret_key.clone()),
        ))
    }
}

const SIGN_TTL: Duration = Duration::from_secs(6 * 3600);

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())
}

/// Run an async block from a blocking thread (jobs and the scheduler run on the blocking pool).
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Handle::current().block_on(f)
}

async fn check(res: reqwest::Response) -> Result<reqwest::Response, String> {
    if res.status().is_success() {
        return Ok(res);
    }
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    let code = body
        .split("<Code>")
        .nth(1)
        .and_then(|s| s.split("</Code>").next())
        .unwrap_or("")
        .to_string();
    Err(format!("S3 returned {status} {code}").trim().to_string())
}

pub fn upload(cfg: &S3Config, key: &str, path: &Path) -> Result<(), String> {
    let (bucket, creds) = cfg.bucket()?;
    let url = bucket.put_object(Some(&creds), key).sign(SIGN_TTL);
    let len = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    let path = path.to_path_buf();
    block_on(async move {
        let file = tokio::fs::File::open(&path).await.map_err(|e| e.to_string())?;
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
        let res = client()?
            .put(url)
            .header(reqwest::header::CONTENT_LENGTH, len)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("upload failed: {e}"))?;
        check(res).await.map(|_| ())
    })
}

pub fn download(cfg: &S3Config, key: &str, dest: &Path) -> Result<(), String> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let (bucket, creds) = cfg.bucket()?;
    let url = bucket.get_object(Some(&creds), key).sign(SIGN_TTL);
    let dest = dest.to_path_buf();
    block_on(async move {
        let res = check(
            client()?
                .get(url)
                .send()
                .await
                .map_err(|e| format!("download failed: {e}"))?,
        )
        .await?;
        let mut file = tokio::fs::File::create(&dest).await.map_err(|e| e.to_string())?;
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            file.write_all(&chunk.map_err(|e| e.to_string())?)
                .await
                .map_err(|e| e.to_string())?;
        }
        file.flush().await.map_err(|e| e.to_string())
    })
}

pub fn delete(cfg: &S3Config, key: &str) -> Result<(), String> {
    let (bucket, creds) = cfg.bucket()?;
    let url = bucket.delete_object(Some(&creds), key).sign(SIGN_TTL);
    block_on(async move {
        let res = client()?.delete(url).send().await.map_err(|e| e.to_string())?;
        check(res).await.map(|_| ())
    })
}

/// Write and delete a small object to verify credentials and permissions.
pub fn test(cfg: &S3Config) -> Result<(), String> {
    let (bucket, creds) = cfg.bucket()?;
    let key = cfg.key(".cloudpanel-test");
    let put = bucket.put_object(Some(&creds), &key).sign(SIGN_TTL);
    let del = bucket.delete_object(Some(&creds), &key).sign(SIGN_TTL);
    block_on(async move {
        let c = client()?;
        check(c.put(put).body("ok").send().await.map_err(|e| e.to_string())?).await?;
        check(c.delete(del).send().await.map_err(|e| e.to_string())?)
            .await
            .map(|_| ())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_keys() {
        let mut c = S3Config {
            endpoint: "https://s3.example.com".into(),
            region: "eu".into(),
            bucket: "backups".into(),
            access_key: "a".into(),
            secret_key: "b".into(),
            prefix: "/server1/".into(),
            path_style: true,
        };
        assert!(c.validate().is_ok());
        assert_eq!(c.key("x.tar.gz"), "server1/x.tar.gz");
        c.bucket = "Bad Bucket".into();
        assert!(c.validate().is_err());
        c.bucket = "ok".into();
        c.endpoint = "file:///etc".into();
        assert!(c.validate().is_err());
    }
}
