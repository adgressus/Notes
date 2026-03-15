use std::time::SystemTime;

pub fn build_blob_url(container_sas_url: &str, blob_name: &str) -> String {
    if let Some(query_start) = container_sas_url.find('?') {
        let base = &container_sas_url[..query_start];
        let query = &container_sas_url[query_start..];
        format!("{}/{}{}", base.trim_end_matches('/'), blob_name, query)
    } else {
        format!("{}/{}", container_sas_url.trim_end_matches('/'), blob_name)
    }
}

fn build_list_url(container_sas_url: &str) -> String {
    if let Some(query_start) = container_sas_url.find('?') {
        let base = &container_sas_url[..query_start];
        let query = &container_sas_url[query_start + 1..];
        format!("{}?restype=container&comp=list&{}", base, query)
    } else {
        format!("{}?restype=container&comp=list", container_sas_url)
    }
}

pub async fn download(container_sas_url: &str, blob_name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);
    let client = reqwest::Client::new();
    let response = client.get(&blob_url)
        .header("x-ms-version", "2020-10-02")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("blob download failed ({}): {}", status, body).into());
    }

    Ok(response.bytes().await?.to_vec())
}

pub async fn upload(container_sas_url: &str, blob_name: &str, body: Vec<u8>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);
    let client = reqwest::Client::new();
    let response = client.put(&blob_url)
        .header("x-ms-blob-type", "BlockBlob")
        .header("x-ms-version", "2020-10-02")
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("blob upload failed ({}): {}", status, body).into());
    }

    Ok(())
}

pub async fn last_modified(container_sas_url: &str, blob_name: &str) -> Result<Option<SystemTime>, Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);
    let client = reqwest::Client::new();
    let response = client.head(&blob_url)
        .header("x-ms-version", "2020-10-02")
        .send()
        .await?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let modified = response.headers().get("Last-Modified")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| httpdate::parse_http_date(s).ok());

    Ok(modified)
}

pub async fn list_keys(container_sas_url: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let list_url = build_list_url(container_sas_url);
    let client = reqwest::Client::new();
    let response = client.get(&list_url)
        .header("x-ms-version", "2020-10-02")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("blob list failed ({}): {}", status, body).into());
    }

    let body = response.text().await?;
    let mut names = Vec::new();
    for segment in body.split("<Name>") {
        if let Some(end) = segment.find("</Name>") {
            names.push(segment[..end].to_string());
        }
    }
    names.sort();
    Ok(names)
}
