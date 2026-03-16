use std::time::SystemTime;

/// Parse Azure Storage XML error responses into a human-readable message.
/// When `multiline` is true, formats on separate lines;
pub fn parse_azure_error(status: reqwest::StatusCode, raw: &str, multiline: bool) -> String {
    fn extract_tag(xml: &str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close)? + start;
        Some(xml[start..end].to_string())
    }

    let code = extract_tag(raw, "Code");
    let message = extract_tag(raw, "Message");
    let detail = extract_tag(raw, "AuthenticationErrorDetail");

    if code.is_none() {
        return format!("{}: {}", status, raw);
    }

    let mut parts = vec![format!("Code: {}", code.unwrap())];
    if let Some(m) = message {
        if let Some(first_line) = m.lines().next() {
            parts.push(format!("Message: {}", first_line));
        }
    }
    if let Some(d) = detail {
        parts.push(format!("Detail: {}", d));
    }

    if multiline {
        format!("{}\n  {}", status, parts.join("\n  "))
    } else {
        format!("{} — {}", status, parts.join("; "))
    }
}

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
        return Err(format!("blob download failed: {}", parse_azure_error(status, &body, true)).into());
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
        return Err(format!("blob upload failed: {}", parse_azure_error(status, &body, true)).into());
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
        return Err(format!("blob list failed: {}", parse_azure_error(status, &body, true)).into());
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
