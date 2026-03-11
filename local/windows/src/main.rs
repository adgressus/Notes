// #![windows_subsystem = "windows"]  // Commented out for debugging

use std::mem::zeroed;
use std::path::PathBuf;
use std::time::SystemTime;
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Graphics::Gdi::*,
        Security::Credentials::*,
        System::LibraryLoader::GetModuleHandleW,
        UI::Controls::Dialogs::*,
        UI::Input::KeyboardAndMouse::{SetFocus, GetKeyState},
        UI::WindowsAndMessaging::*,
    },
};

mod microsoft_auth;

static mut EDIT_HWND: HWND = HWND(std::ptr::null_mut());
static mut MAIN_HWND: HWND = HWND(std::ptr::null_mut());
static mut INITIAL_CONTENT: Option<String> = None;
static mut CURRENT_FILE_PATH: Option<PathBuf> = None;
static mut CURRENT_FILE_NAME: Option<String> = None;
static mut CONTAINER_SAS_URL: Option<String> = None;
static mut REFRESH_TOKEN: Option<String> = None;

const CREDENTIAL_TARGET: &str = "NotesApp/RefreshToken";

/// Saves the refresh token to Windows Credential Manager
fn save_refresh_token(token: &str) {
    let target_wide: Vec<u16> = CREDENTIAL_TARGET.encode_utf16().chain(std::iter::once(0)).collect();
    let mut blob = token.as_bytes().to_vec();
    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_wide.as_ptr() as *mut _),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..unsafe { zeroed() }
    };
    unsafe {
        if let Err(e) = CredWriteW(&cred, 0) {
            eprintln!("[Cred] Failed to save refresh token: {}", e);
        } else {
            println!("[Cred] Refresh token saved to Credential Manager");
        }
    }
}

/// Loads the refresh token from Windows Credential Manager
fn load_refresh_token() -> Option<String> {
    let target_wide: Vec<u16> = CREDENTIAL_TARGET.encode_utf16().chain(std::iter::once(0)).collect();
    let mut cred_ptr = std::ptr::null_mut();
    unsafe {
        if CredReadW(PCWSTR(target_wide.as_ptr()), CRED_TYPE_GENERIC, 0, &mut cred_ptr).is_ok() {
            let cred = &*cred_ptr;
            let blob = std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize);
            let token = String::from_utf8_lossy(blob).to_string();
            CredFree(cred_ptr as *const _);
            println!("[Cred] Loaded refresh token from Credential Manager");
            Some(token)
        } else {
            println!("[Cred] No saved refresh token found");
            None
        }
    }
}

/// Deletes the refresh token from Windows Credential Manager
fn delete_refresh_token() {
    let target_wide: Vec<u16> = CREDENTIAL_TARGET.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = CredDeleteW(PCWSTR(target_wide.as_ptr()), CRED_TYPE_GENERIC, 0);
        println!("[Cred] Refresh token deleted from Credential Manager");
    }
}

/// Builds the full blob URL from the container SAS URL and a blob name
fn build_blob_url(container_sas_url: &str, blob_name: &str) -> String {
    // SAS URL format: https://account.blob.core.windows.net/container?<sas_params>
    if let Some(query_start) = container_sas_url.find('?') {
        let base = &container_sas_url[..query_start];
        let query = &container_sas_url[query_start..]; // includes '?'
        format!("{}/{}{}", base.trim_end_matches('/'), blob_name, query)
    } else {
        format!("{}/{}", container_sas_url.trim_end_matches('/'), blob_name)
    }
}

/// Builds the list blobs URL from the container SAS URL
fn build_list_url(container_sas_url: &str) -> String {
    // Append restype=container&comp=list to the SAS query
    if let Some(query_start) = container_sas_url.find('?') {
        let base = &container_sas_url[..query_start];
        let query = &container_sas_url[query_start + 1..]; // skip '?'
        format!("{}?restype=container&comp=list&{}", base, query)
    } else {
        format!("{}?restype=container&comp=list", container_sas_url)
    }
}

/// Fetches a blob from Azure Blob Storage using the container SAS URL
/// Returns the content and the last modified timestamp
async fn fetch_notes_from_azure(container_sas_url: &str, blob_name: &str) -> std::result::Result<(String, Option<SystemTime>), Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);
    println!("[Azure] Fetching blob '{}'", blob_name);

    let client = reqwest::Client::new();
    let response = client.get(&blob_url)
        .header("x-ms-version", "2020-10-02")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Azure blob fetch failed ({}): {}", status, body).into());
    }

    // Parse Last-Modified header
    let last_modified = response.headers().get("Last-Modified")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            // Format: "Thu, 01 Jan 2026 00:00:00 GMT"
            httpdate::parse_http_date(s).ok()
        });
    println!("[Azure] Last modified: {:?}", last_modified);

    let content = response.text().await?;
    println!("[Azure] Content fetched successfully, {} bytes", content.len());

    Ok((content, last_modified))
}

/// Gets the path to the local notes file
fn get_notes_path() -> Option<std::path::PathBuf> {
    // Use the current file path if set, otherwise default to notes.txt in USERPROFILE
    unsafe {
        if let Some(ref path) = CURRENT_FILE_PATH {
            return Some(path.clone());
        }
    }
    std::env::var("USERPROFILE").ok().map(|home| std::path::Path::new(&home).join("notes.txt"))
}

/// Gets the current S3 key (filename)
fn get_current_key() -> String {
    unsafe {
        CURRENT_FILE_NAME.clone().unwrap_or_else(|| "notes.txt".to_string())
    }
}

/// Gets the last modified timestamp of the local notes file
fn get_local_file_modified_time() -> Option<SystemTime> {
    get_notes_path().and_then(|path| {
        std::fs::metadata(&path).ok().and_then(|meta| meta.modified().ok())
    })
}

/// Reads the local notes file
fn read_local_notes() -> Option<String> {
    get_notes_path().and_then(|path| std::fs::read_to_string(&path).ok())
}

/// Lists all blobs in the Azure Blob container using the SAS URL
async fn list_azure_blobs(container_sas_url: &str) -> std::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let list_url = build_list_url(container_sas_url);
    println!("[Azure List] Listing blobs...");

    let client = reqwest::Client::new();
    let response = client.get(&list_url)
        .header("x-ms-version", "2020-10-02")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Azure list blobs failed ({}): {}", status, body).into());
    }

    let body = response.text().await?;

    // Parse the XML response to extract blob names
    // The response contains <Blob><Name>...</Name></Blob> elements
    let mut names = Vec::new();
    for segment in body.split("<Name>") {
        if let Some(end) = segment.find("</Name>") {
            names.push(segment[..end].to_string());
        }
    }

    println!("[Azure List] Found {} blobs", names.len());
    Ok(names)
}

/// Uploads content to Azure Blob Storage using the container SAS URL
async fn upload_notes_to_azure(container_sas_url: &str, blob_name: &str, content: &str) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);
    println!("[Azure Upload] Uploading blob '{}'", blob_name);

    let client = reqwest::Client::new();
    let response = client.put(&blob_url)
        .header("x-ms-blob-type", "BlockBlob")
        .header("x-ms-version", "2020-10-02")
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(content.to_string())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Azure upload failed ({}): {}", status, body).into());
    }

    println!("[Azure Upload] Upload successful");
    Ok(())
}

/// Calls the get_url endpoint to exchange a refresh token for a new SAS URL
async fn call_get_url(refresh_token: &str) -> std::result::Result<(String, Option<String>), Box<dyn std::error::Error + Send + Sync>> {
    println!("[GetURL] Calling get_url with refresh token...");
    let client = reqwest::Client::new();
    let resp = client
        .post("https://notes-auth-func.azurewebsites.net/api/get_url")
        .body(refresh_token.to_string())
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("get_url failed ({}): {}", status, body).into());
    }

    let body = resp.text().await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;

    let url = json.get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'url' in get_url response")?
        .to_string();

    let new_token = json.get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    println!("[GetURL] Successfully obtained new SAS URL");
    Ok((url, new_token))
}

/// Attempts to refresh the SAS URL. First tries using the refresh token,
/// then falls back to showing the login dialog.
/// Returns the new SAS URL if successful, or None if the user cancels.
unsafe fn refresh_credentials(rt: &tokio::runtime::Runtime) -> Option<String> {
    println!("[Refresh] Attempting to refresh credentials...");

    // Step 1: Try to get a new URL using the refresh token
    if let Some(ref token) = REFRESH_TOKEN {
        println!("[Refresh] Trying get_url with existing refresh token...");
        match rt.block_on(call_get_url(token)) {
            Ok((new_sas, new_token)) => {
                println!("[Refresh] Successfully refreshed SAS URL");
                CONTAINER_SAS_URL = Some(new_sas.clone());
                if let Some(t) = new_token {
                    save_refresh_token(&t);
                    REFRESH_TOKEN = Some(t);
                }
                return Some(new_sas);
            }
            Err(e) => {
                eprintln!("[Refresh] Failed to refresh SAS URL: {}", e);
            }
        }
    } else {
        println!("[Refresh] No refresh token available, skipping get_url");
    }

    // Step 2: Show login dialog to re-authenticate
    println!("[Refresh] Showing login dialog for re-authentication...");
    let template = build_login_dialog_template();
    let instance = GetModuleHandleW(None).unwrap_or_default();
    DialogBoxIndirectParamW(
        instance,
        template.as_ptr() as *const DLGTEMPLATE,
        MAIN_HWND,
        Some(login_dlg_proc),
        LPARAM(0),
    );

    // Check if login was successful
    CONTAINER_SAS_URL.clone()
}

/// Fetches notes from Azure with automatic credential refresh on failure
unsafe fn fetch_notes_with_retry(
    rt: &tokio::runtime::Runtime,
    blob_name: &str,
) -> std::result::Result<(String, Option<SystemTime>), Box<dyn std::error::Error + Send + Sync>> {
    let sas = CONTAINER_SAS_URL.clone().ok_or("No SAS URL configured")?;

    match rt.block_on(fetch_notes_from_azure(&sas, blob_name)) {
        Ok(result) => Ok(result),
        Err(e) => {
            eprintln!("[Retry] Fetch failed: {}, attempting credential refresh...", e);
            match refresh_credentials(rt) {
                Some(new_sas) => rt.block_on(fetch_notes_from_azure(&new_sas, blob_name)),
                None => Err(e),
            }
        }
    }
}

/// Uploads notes to Azure with automatic credential refresh on failure
unsafe fn upload_notes_with_retry(
    rt: &tokio::runtime::Runtime,
    blob_name: &str,
    content: &str,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sas = CONTAINER_SAS_URL.clone().ok_or("No SAS URL configured")?;

    match rt.block_on(upload_notes_to_azure(&sas, blob_name, content)) {
        Ok(result) => Ok(result),
        Err(e) => {
            eprintln!("[Retry] Upload failed: {}, attempting credential refresh...", e);
            match refresh_credentials(rt) {
                Some(new_sas) => rt.block_on(upload_notes_to_azure(&new_sas, blob_name, content)),
                None => Err(e),
            }
        }
    }
}

/// Lists Azure blobs with automatic credential refresh on failure
unsafe fn list_blobs_with_retry(
    rt: &tokio::runtime::Runtime,
) -> std::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let sas = CONTAINER_SAS_URL.clone().ok_or("No SAS URL configured")?;

    match rt.block_on(list_azure_blobs(&sas)) {
        Ok(result) => Ok(result),
        Err(e) => {
            eprintln!("[Retry] List blobs failed: {}, attempting credential refresh...", e);
            match refresh_credentials(rt) {
                Some(new_sas) => rt.block_on(list_azure_blobs(&new_sas)),
                None => Err(e),
            }
        }
    }
}

fn main() -> Result<()> {
    // Check for file path argument, otherwise default to notes.txt
    let args: Vec<String> = std::env::args().collect();
    let (file_path, file_name) = if args.len() > 1 {
        let path = PathBuf::from(&args[1]);
        let name = path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "notes.txt".to_string());
        (path, name)
    } else {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
        (std::path::Path::new(&home).join("notes.txt"), "notes.txt".to_string())
    };
    
    // Initialize file path and name
    unsafe {
        CURRENT_FILE_PATH = Some(file_path.clone());
        CURRENT_FILE_NAME = Some(file_name.clone());
    }
    
    println!("[Main] File path: {:?}", file_path);
    println!("[Main] File name: {}", file_name);
    
    // Check if SAS URL was passed via environment variable (from parent process)
    if let Ok(sas) = std::env::var("NOTES_SAS_URL") {
        if !sas.is_empty() {
            println!("[Main] Found SAS URL from environment");
            unsafe { CONTAINER_SAS_URL = Some(sas); }
        }
    }
    if let Ok(token) = std::env::var("NOTES_REFRESH_TOKEN") {
        if !token.is_empty() {
            unsafe { REFRESH_TOKEN = Some(token); }
        }
    }
    
    // Try loading refresh token from Credential Manager if we don't have one yet
    let has_refresh = unsafe { REFRESH_TOKEN.is_some() };
    let has_sas = unsafe { CONTAINER_SAS_URL.is_some() };
    if !has_sas && !has_refresh {
        if let Some(saved_token) = load_refresh_token() {
            unsafe { REFRESH_TOKEN = Some(saved_token); }
        }
    }
    
    // If we have a refresh token but no SAS URL, try to get one
    let has_refresh = unsafe { REFRESH_TOKEN.is_some() };
    let has_sas = unsafe { CONTAINER_SAS_URL.is_some() };
    if !has_sas && has_refresh {
        println!("[Main] Have refresh token, trying to get SAS URL...");
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        let token = unsafe { REFRESH_TOKEN.clone().unwrap() };
        match rt.block_on(call_get_url(&token)) {
            Ok((sas_url, new_token)) => {
                println!("[Main] Successfully obtained SAS URL from saved token");
                unsafe { CONTAINER_SAS_URL = Some(sas_url); }
                if let Some(t) = new_token {
                    save_refresh_token(&t);
                    unsafe { REFRESH_TOKEN = Some(t); }
                }
            }
            Err(e) => {
                eprintln!("[Main] Failed to get SAS URL from saved token: {}", e);
                delete_refresh_token();
                unsafe { REFRESH_TOKEN = None; }
            }
        }
    }
    
    // If no SAS URL is set, show login dialog
    let has_sas = unsafe { CONTAINER_SAS_URL.is_some() };
    if !has_sas {
        println!("[Main] No Azure SAS URL, showing login dialog");
        unsafe {
            let template = build_login_dialog_template();
            let instance = GetModuleHandleW(None).unwrap_or_default();
            DialogBoxIndirectParamW(
                instance,
                template.as_ptr() as *const windows::Win32::UI::WindowsAndMessaging::DLGTEMPLATE,
                None,
                Some(login_dlg_proc),
                LPARAM(0),
            );
        }
    }

    // Fetch content from Azure Blob Storage before starting the GUI
    println!("[Main] SAS URL after login: {}", if unsafe { CONTAINER_SAS_URL.is_some() } { "present" } else { "missing" });
    if unsafe { CONTAINER_SAS_URL.is_some() } {
        println!("[Main] Creating Tokio runtime...");
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        println!("[Main] Fetching notes from Azure...");
        match unsafe { fetch_notes_with_retry(&rt, &file_name) } {
            Ok((remote_content, remote_modified)) => {
                println!("[Main] Successfully fetched {} bytes from Azure", remote_content.len());
                
                // Compare timestamps to decide which source to use
                let local_modified = get_local_file_modified_time();
                println!("[Main] Local file last modified: {:?}", local_modified);
                
                let use_remote = match (remote_modified, local_modified) {
                    (Some(remote_time), Some(local_time)) => {
                        if remote_time > local_time {
                            println!("[Main] Remote is newer, using remote content and overwriting local file");
                            if let Some(path) = get_notes_path() {
                                if let Err(e) = std::fs::write(&path, &remote_content) {
                                    eprintln!("[Main] Failed to overwrite local file: {}", e);
                                }
                            }
                            true
                        } else {
                            println!("[Main] Local file is newer or same age, using local content");
                            false
                        }
                    }
                    (Some(_), None) => {
                        println!("[Main] No local file exists, using remote content");
                        if let Some(path) = get_notes_path() {
                            if let Err(e) = std::fs::write(&path, &remote_content) {
                                eprintln!("[Main] Failed to save remote content to local file: {}", e);
                            }
                        }
                        true
                    }
                    _ => {
                        println!("[Main] Could not determine remote timestamp, using remote content");
                        true
                    }
                };
                
                let content = if use_remote {
                    remote_content
                } else {
                    read_local_notes().unwrap_or(remote_content)
                };
                
                unsafe { INITIAL_CONTENT = Some(content); }
            }
            Err(e) => {
                eprintln!("[Main] ERROR: Failed to fetch notes from Azure: {}", e);
                if let Some(content) = read_local_notes() {
                    println!("[Main] Falling back to local file");
                    unsafe { INITIAL_CONTENT = Some(content); }
                }
            }
        }
    } else {
        println!("[Main] No SAS URL available, reading local file only");
        if let Some(content) = read_local_notes() {
            unsafe { INITIAL_CONTENT = Some(content); }
        }
    }

    unsafe {
        let instance = GetModuleHandleW(None)?;

        // Register the window class
        let class_name = w!("NotesWindowClass");

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as *mut _),
            lpszClassName: class_name,
            ..zeroed()
        };

        RegisterClassExW(&wc);

        // Create the main window with filename in title
        let window_title = format!("Notes - {}\0", file_name);
        let window_title_wide: Vec<u16> = window_title.encode_utf16().collect();
        
        MAIN_HWND = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            PCWSTR(window_title_wide.as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            600,
            None,
            None,
            instance,
            None,
        )?;

        // Message loop
        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            // Intercept Ctrl+Shift+S for Save As
            if msg.message == WM_KEYDOWN && msg.wParam.0 as u16 == 0x53 {
                let ctrl = GetKeyState(0x11) < 0;
                let shift = GetKeyState(0x10) < 0;
                if ctrl && shift {
                    show_save_as_dialog(MAIN_HWND);
                    continue;
                }
            }
            // Intercept Ctrl+N for New File
            if msg.message == WM_KEYDOWN && msg.wParam.0 as u16 == 0x4E {
                let ctrl = GetKeyState(0x11) < 0;
                let shift = GetKeyState(0x10) < 0;
                if ctrl && !shift {
                    show_new_file_dialog();
                    continue;
                }
            }
            // Intercept Ctrl+O for Open File from S3
            if msg.message == WM_KEYDOWN && msg.wParam.0 as u16 == 0x4F {
                let ctrl = GetKeyState(0x11) < 0;
                if ctrl {
                    show_open_file_dialog();
                    continue;
                }
            }
            let _ = TranslateMessage(&msg);
            let _ = DispatchMessageW(&msg);
        }

        Ok(())
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            // Create a multiline edit control (text area)
            let instance = GetModuleHandleW(None).unwrap();
            
            EDIT_HWND = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                w!("EDIT"),
                w!(""),
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL 
                    | WINDOW_STYLE(ES_MULTILINE as u32)
                    | WINDOW_STYLE(ES_AUTOVSCROLL as u32)
                    | WINDOW_STYLE(ES_AUTOHSCROLL as u32)
                    | WINDOW_STYLE(ES_WANTRETURN as u32),
                0,
                0,
                800,
                600,
                hwnd,
                HMENU(1 as *mut _),
                instance,
                None,
            ).unwrap_or_default();

            // Set a nice font
            let font = CreateFontW(
                -16,                        // Height
                0,                          // Width
                0,                          // Escapement
                0,                          // Orientation
                FW_NORMAL.0 as i32,         // Weight
                0,                          // Italic
                0,                          // Underline
                0,                          // StrikeOut
                DEFAULT_CHARSET.0 as u32,   // CharSet
                OUT_DEFAULT_PRECIS.0 as u32,
                CLIP_DEFAULT_PRECIS.0 as u32,
                CLEARTYPE_QUALITY.0 as u32,
                (FF_DONTCARE.0 | DEFAULT_PITCH.0) as u32,
                w!("Consolas"),
            );

            if !font.is_invalid() {
                SendMessageW(EDIT_HWND, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
            }

            // Set initial content from S3 if available
            if let Some(content) = INITIAL_CONTENT.take() {
                // Convert Unix line endings (\n) to Windows line endings (\r\n)
                let content = content.replace("\r\n", "\n").replace("\n", "\r\n");
                let wide: Vec<u16> = content.encode_utf16().chain(std::iter::once(0)).collect();
                SetWindowTextW(EDIT_HWND, PCWSTR(wide.as_ptr())).ok();
            }

            // Set focus to the edit control
            let _ = SetFocus(EDIT_HWND);

            LRESULT(0)
        }
        WM_SIZE => {
            // Resize the edit control to fill the window
            let width = (lparam.0 & 0xFFFF) as i32;
            let height = ((lparam.0 >> 16) & 0xFFFF) as i32;
            
            if !EDIT_HWND.is_invalid() {
                let _ = SetWindowPos(
                    EDIT_HWND,
                    None,
                    0,
                    0,
                    width,
                    height,
                    SWP_NOZORDER,
                );
            }
            LRESULT(0)
        }
        WM_SETFOCUS => {
            // When main window gets focus, pass it to edit control
            if !EDIT_HWND.is_invalid() {
                let _ = SetFocus(EDIT_HWND);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            // Save the text content to the current file path
            if !EDIT_HWND.is_invalid() {
                let text_len = GetWindowTextLengthW(EDIT_HWND) as usize;
                if text_len > 0 {
                    let mut buffer: Vec<u16> = vec![0; text_len + 1];
                    GetWindowTextW(EDIT_HWND, &mut buffer);
                    // Remove null terminator and convert to String
                    let text = String::from_utf16_lossy(&buffer[..text_len]);
                    
                    // Save to current file path
                    if let Some(path) = get_notes_path() {
                        if let Err(e) = std::fs::write(&path, &text) {
                            eprintln!("[Save] Failed to save notes: {}", e);
                        } else {
                            println!("[Save] Notes saved to {:?}", path);
                        }
                    }
                    
                    // Upload to Azure Blob Storage if SAS URL is configured
                    if CONTAINER_SAS_URL.is_some() {
                        let key = get_current_key();
                        println!("[Save] Uploading to Azure with key '{}'...", key);
                        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
                        match upload_notes_with_retry(&rt, &key, &text) {
                            Ok(_) => println!("[Save] Successfully uploaded to Azure"),
                            Err(e) => eprintln!("[Save] Failed to upload to Azure: {}", e),
                        }
                    }
                }
            }
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Shows a Save As dialog and updates the current file path and name
unsafe fn show_save_as_dialog(hwnd: HWND) {
    use std::os::windows::ffi::OsStrExt;
    
    // Create filename buffer with current name as default
    let current_name = CURRENT_FILE_NAME.clone().unwrap_or_else(|| "notes.txt".to_string());
    let mut filename_buffer: Vec<u16> = current_name.encode_utf16().collect();
    filename_buffer.resize(260, 0);
    
    // Set up initial directory
    let initial_dir_wide: Vec<u16> = CURRENT_FILE_PATH.as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.as_os_str().encode_wide().chain(std::iter::once(0)).collect())
        .unwrap_or_default();
    
    let filter: Vec<u16> = "Text Files\0*.txt\0All Files\0*.*\0\0".encode_utf16().collect();
    
    let mut ofn: OPENFILENAMEW = zeroed();
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = PCWSTR(filter.as_ptr());
    ofn.lpstrFile = PWSTR(filename_buffer.as_mut_ptr());
    ofn.nMaxFile = 260;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = w!("txt");
    if !initial_dir_wide.is_empty() {
        ofn.lpstrInitialDir = PCWSTR(initial_dir_wide.as_ptr());
    }
    
    if !GetSaveFileNameW(&mut ofn).as_bool() {
        return;
    }
    
    // Parse the selected path
    let len = filename_buffer.iter().position(|&c| c == 0).unwrap_or(filename_buffer.len());
    let new_path = PathBuf::from(String::from_utf16_lossy(&filename_buffer[..len]));
    let new_filename = new_path.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "notes.txt".to_string());
    
    println!("[SaveAs] New path: {:?}, New filename: {}", new_path, new_filename);
    
    // Update global state and window title
    CURRENT_FILE_PATH = Some(new_path.clone());
    CURRENT_FILE_NAME = Some(new_filename.clone());
    let title: Vec<u16> = format!("Notes - {}\0", new_filename).encode_utf16().collect();
    SetWindowTextW(hwnd, PCWSTR(title.as_ptr())).ok();
    
    // Get current text and save
    let text_len = GetWindowTextLengthW(EDIT_HWND) as usize;
    if text_len == 0 {
        return;
    }
    
    let mut buffer: Vec<u16> = vec![0; text_len + 1];
    GetWindowTextW(EDIT_HWND, &mut buffer);
    let text = String::from_utf16_lossy(&buffer[..text_len]);
    
    if let Err(e) = std::fs::write(&new_path, &text) {
        eprintln!("[SaveAs] Failed to save: {}", e);
    } else {
        println!("[SaveAs] Saved to {:?}", new_path);
    }
    
    // Upload to Azure if SAS URL is configured
    if CONTAINER_SAS_URL.is_some() {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        if let Err(e) = upload_notes_with_retry(&rt, &new_filename, &text) {
            eprintln!("[SaveAs] Azure upload failed: {}", e);
        }
    }
}

/// Generates a filename from the current local time in format: "Month Day, Hour AM/PM (Year).txt"
fn generate_filename_from_time() -> String {
    let st = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };

    let month_names = ["January", "February", "March", "April", "May", "June",
                       "July", "August", "September", "October", "November", "December"];
    let month_name = month_names[(st.wMonth as usize).saturating_sub(1).min(11)];

    let (hour_12, am_pm) = match st.wHour {
        0 => (12, "AM"),
        1..=11 => (st.wHour, "AM"),
        12 => (12, "PM"),
        _ => (st.wHour - 12, "PM"),
    };

    format!("{} {}, {} {} ({}).txt", month_name, st.wDay, hour_12, am_pm, st.wYear)
}

/// Creates a new file with auto-generated name and spawns a new process for it
unsafe fn show_new_file_dialog() {
    use std::os::windows::ffi::OsStrExt;
    
    // Generate auto-named file in ~/Notes/ directory
    let new_filename = generate_filename_from_time();
    
    // Get Notes directory path (USERPROFILE/Notes/)
    let notes_dir = match std::env::var("USERPROFILE") {
        Ok(home) => std::path::Path::new(&home).join("Notes"),
        Err(_) => {
            eprintln!("[NewFile] USERPROFILE not set");
            return;
        }
    };
    
    // Create Notes directory if it doesn't exist
    if !notes_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&notes_dir) {
            eprintln!("[NewFile] Failed to create Notes directory: {}", e);
            return;
        }
    }
    
    let new_path = notes_dir.join(&new_filename);
    
    // Deduplicate: if file exists, append -1, -2, etc.
    let (new_path, new_filename) = if new_path.exists() {
        let stem = new_filename.trim_end_matches(".txt");
        let mut counter = 1;
        loop {
            let candidate_name = format!("{}-{}.txt", stem, counter);
            let candidate_path = notes_dir.join(&candidate_name);
            if !candidate_path.exists() {
                break (candidate_path, candidate_name);
            }
            counter += 1;
        }
    } else {
        (new_path, new_filename)
    };
    
    println!("[NewFile] Opening file: {:?}", new_path);
    
    // Check if local file exists and get its modification time
    let local_exists = new_path.exists();
    let local_modified = std::fs::metadata(&new_path).ok().and_then(|m| m.modified().ok());
    
    // Check Azure for existing file
    let mut remote_content: Option<String> = None;
    let mut remote_modified: Option<SystemTime> = None;
    
    if CONTAINER_SAS_URL.is_some() {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        match fetch_notes_with_retry(&rt, &new_filename) {
            Ok((content, modified)) => {
                remote_content = Some(content);
                remote_modified = modified;
                println!("[NewFile] Found Azure blob, modified: {:?}", remote_modified);
            }
            Err(e) => {
                println!("[NewFile] No Azure blob found or error: {}", e);
            }
        }
    }
    
    // Determine what to do based on existence and timestamps
    match (local_exists, remote_content.is_some()) {
        (false, false) => {
            // Neither exists - create new empty file locally and in Azure
            println!("[NewFile] Creating new empty file");
            if let Err(e) = std::fs::write(&new_path, "") {
                eprintln!("[NewFile] Failed to create file: {}", e);
                return;
            }
            if CONTAINER_SAS_URL.is_some() {
                let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
                if let Err(e) = upload_notes_with_retry(&rt, &new_filename, "") {
                    eprintln!("[NewFile] Azure upload failed: {}", e);
                }
            }
        }
        (true, false) => {
            // Local exists, no remote - use local as-is
            println!("[NewFile] Using existing local file (no remote version)");
        }
        (false, true) => {
            // Remote exists, no local - download from Azure
            println!("[NewFile] Downloading from Azure (no local file)");
            if let Some(content) = &remote_content {
                if let Err(e) = std::fs::write(&new_path, content) {
                    eprintln!("[NewFile] Failed to save remote content locally: {}", e);
                }
            }
        }
        (true, true) => {
            // Both exist - compare timestamps
            match (remote_modified, local_modified) {
                (Some(remote_time), Some(local_time)) if remote_time > local_time => {
                    println!("[NewFile] Remote is newer, overwriting local file");
                    if let Some(content) = &remote_content {
                        if let Err(e) = std::fs::write(&new_path, content) {
                            eprintln!("[NewFile] Failed to overwrite local file: {}", e);
                        }
                    }
                }
                _ => {
                    println!("[NewFile] Local file is newer or same age, using local");
                }
            }
        }
    }
    
    // Spawn a new instance of this program with the file path as argument
    let exe_path = std::env::current_exe().expect("Failed to get current exe path");
    let mut cmd = std::process::Command::new(&exe_path);
    cmd.arg(&new_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    // Pass SAS URL and refresh token to the child process
    if let Some(ref sas) = CONTAINER_SAS_URL {
        cmd.env("NOTES_SAS_URL", sas);
    }
    if let Some(ref token) = REFRESH_TOKEN {
        cmd.env("NOTES_REFRESH_TOKEN", token);
    }
    match cmd.spawn() {
        Ok(_) => println!("[NewFile] Spawned new window for {:?}", new_path),
        Err(e) => eprintln!("[NewFile] Failed to spawn new window: {}", e),
    }
}

// Dialog control IDs for the file picker
const IDC_FILE_LIST: i32 = 101;
const IDC_OK: i32 = 1;
const IDC_CANCEL: i32 = 2;

// Dialog control IDs for the login dialog
const IDC_LOGIN_BTN: i32 = 201;
const IDC_LOGIN_CANCEL: i32 = 202;
const IDC_LINK_CODE_EDIT: i32 = 203;
const IDC_LINK_ACCOUNTS_BTN: i32 = 204;
const ES_NUMBER: u32 = 0x2000;
const EM_LIMITTEXT: u32 = 0x00C5;

static mut PICKER_KEYS: Option<Vec<String>> = None;
static mut PICKER_SELECTED: Option<String> = None;

/// Dialog procedure for the S3 file picker dialog
unsafe extern "system" fn picker_dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, _lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            // Populate the listbox with S3 keys
            let listbox = GetDlgItem(hwnd, IDC_FILE_LIST).unwrap_or_default();
            if let Some(keys) = &PICKER_KEYS {
                for key in keys {
                    let wide: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
                    SendMessageW(listbox, LB_ADDSTRING, WPARAM(0), LPARAM(wide.as_ptr() as isize));
                }
                // Select the first item by default
                if !keys.is_empty() {
                    SendMessageW(listbox, LB_SETCURSEL, WPARAM(0), LPARAM(0));
                }
            }
            1 // TRUE - let system set focus
        }
        WM_COMMAND => {
            let control_id = (wparam.0 & 0xFFFF) as i32;
            let notification = ((wparam.0 >> 16) & 0xFFFF) as u32;

            if control_id == IDC_OK || (control_id == IDC_FILE_LIST && notification == LBN_DBLCLK) {
                // Get the selected item
                let listbox = GetDlgItem(hwnd, IDC_FILE_LIST).unwrap_or_default();
                let sel = SendMessageW(listbox, LB_GETCURSEL, WPARAM(0), LPARAM(0));
                if sel.0 >= 0 {
                    let len = SendMessageW(listbox, LB_GETTEXTLEN, WPARAM(sel.0 as usize), LPARAM(0));
                    if len.0 > 0 {
                        let mut buf: Vec<u16> = vec![0; (len.0 as usize) + 1];
                        SendMessageW(listbox, LB_GETTEXT, WPARAM(sel.0 as usize), LPARAM(buf.as_mut_ptr() as isize));
                        let text = String::from_utf16_lossy(&buf[..len.0 as usize]);
                        PICKER_SELECTED = Some(text);
                    }
                }
                let _ = EndDialog(hwnd, 1);
                1
            } else if control_id == IDC_CANCEL {
                PICKER_SELECTED = None;
                let _ = EndDialog(hwnd, 0);
                1
            } else {
                0
            }
        }
        WM_CLOSE => {
            PICKER_SELECTED = None;
            let _ = EndDialog(hwnd, 0);
            1
        }
        _ => 0,
    }
}

/// Builds an in-memory DLGTEMPLATE for the file picker dialog
fn build_picker_dialog_template() -> Vec<u16> {
    let mut buf: Vec<u16> = Vec::new();

    // Helper: align to DWORD boundary (4 bytes = 2 u16s)
    fn align4(buf: &mut Vec<u16>) {
        while (buf.len() * 2) % 4 != 0 {
            buf.push(0);
        }
    }

    // DLGTEMPLATE
    let style: u32 = (WS_POPUP.0 | WS_CAPTION.0 | WS_SYSMENU.0 | WS_VISIBLE.0)
        | DS_MODALFRAME as u32
        | DS_SETFONT as u32;
    buf.push(style as u16);
    buf.push((style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle low, high
    buf.push(3); // cdit - number of controls (listbox, OK, Cancel)
    buf.push(50);  // x
    buf.push(50);  // y
    buf.push(220); // cx (width in dialog units)
    buf.push(200); // cy (height in dialog units)
    buf.push(0);   // menu (none)
    buf.push(0);   // class (default)
    // title: "Open from S3"
    for c in "Open from S3".encode_utf16() { buf.push(c); }
    buf.push(0);
    // Font (DS_SETFONT): size then name
    buf.push(9); // point size
    for c in "Segoe UI".encode_utf16() { buf.push(c); }
    buf.push(0);

    // --- Control 1: LISTBOX ---
    align4(&mut buf);
    let lb_style: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_VSCROLL.0 | WS_BORDER.0
        | LBS_NOTIFY as u32 | WS_TABSTOP.0;
    buf.push(lb_style as u16);
    buf.push((lb_style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(10);  // x
    buf.push(10);  // y
    buf.push(200); // cx
    buf.push(160); // cy
    buf.push(IDC_FILE_LIST as u16); // id
    // class: 0x0083 = listbox
    buf.push(0xFFFF);
    buf.push(0x0083);
    buf.push(0); // title (empty)
    buf.push(0); // creation data length

    // --- Control 2: OK button ---
    align4(&mut buf);
    let btn_style: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_DEFPUSHBUTTON as u32;
    buf.push(btn_style as u16);
    buf.push((btn_style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(70);  // x
    buf.push(178); // y
    buf.push(50);  // cx
    buf.push(14);  // cy
    buf.push(IDC_OK as u16); // id
    buf.push(0xFFFF);
    buf.push(0x0080); // button class
    for c in "Open".encode_utf16() { buf.push(c); }
    buf.push(0);
    buf.push(0); // creation data length

    // --- Control 3: Cancel button ---
    align4(&mut buf);
    let btn_style2: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32;
    buf.push(btn_style2 as u16);
    buf.push((btn_style2 >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(130); // x
    buf.push(178); // y
    buf.push(50);  // cx
    buf.push(14);  // cy
    buf.push(IDC_CANCEL as u16); // id
    buf.push(0xFFFF);
    buf.push(0x0080); // button class
    for c in "Cancel".encode_utf16() { buf.push(c); }
    buf.push(0);
    buf.push(0); // creation data length

    buf
}

/// Builds an in-memory DLGTEMPLATE for the login dialog
fn build_login_dialog_template() -> Vec<u16> {
    let mut buf: Vec<u16> = Vec::new();

    fn align4(buf: &mut Vec<u16>) {
        while (buf.len() * 2) % 4 != 0 {
            buf.push(0);
        }
    }

    // DLGTEMPLATE
    let style: u32 = (WS_POPUP.0 | WS_CAPTION.0 | WS_SYSMENU.0 | WS_VISIBLE.0)
        | DS_MODALFRAME as u32
        | DS_SETFONT as u32;
    buf.push(style as u16);
    buf.push((style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle low, high
    buf.push(5); // cdit - number of controls (static text, login button, link code edit, link accounts button, cancel button)
    buf.push(80);  // x
    buf.push(80);  // y
    buf.push(220); // cx
    buf.push(120); // cy
    buf.push(0);   // menu (none)
    buf.push(0);   // class (default)
    // title: "Login Required"
    for c in "Login Required".encode_utf16() { buf.push(c); }
    buf.push(0);
    // Font (DS_SETFONT): size then name
    buf.push(9);
    for c in "Segoe UI".encode_utf16() { buf.push(c); }
    buf.push(0);

    // --- Control 1: Static text label ---
    align4(&mut buf);
    let st_style: u32 = WS_CHILD.0 | WS_VISIBLE.0;
    buf.push(st_style as u16);
    buf.push((st_style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(10);  // x
    buf.push(10);  // y
    buf.push(200); // cx
    buf.push(20);  // cy
    buf.push(0xFFFF_u16); // id (not used)
    // class: 0x0082 = static
    buf.push(0xFFFF);
    buf.push(0x0082);
    for c in "AWS credentials not found. Please log in.".encode_utf16() { buf.push(c); }
    buf.push(0);
    buf.push(0); // creation data length

    // --- Control 2: Sign in with Microsoft button (owner-drawn) ---
    align4(&mut buf);
    let btn_style: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_OWNERDRAW as u32;
    buf.push(btn_style as u16);
    buf.push((btn_style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(35);  // x
    buf.push(40);  // y
    buf.push(150); // cx (~262px wide)
    buf.push(20);  // cy (~37px tall)
    buf.push(IDC_LOGIN_BTN as u16); // id
    buf.push(0xFFFF);
    buf.push(0x0080); // button class
    buf.push(0); // title (empty - we draw it ourselves)
    buf.push(0); // creation data length

    // --- Control 3: Link code textbox (6-digit, number only) ---
    align4(&mut buf);
    let edit_style: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | WS_BORDER.0 | ES_NUMBER;
    buf.push(edit_style as u16);
    buf.push((edit_style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(20);  // x
    buf.push(69);  // y
    buf.push(50);  // cx
    buf.push(14);  // cy
    buf.push(IDC_LINK_CODE_EDIT as u16); // id
    buf.push(0xFFFF);
    buf.push(0x0081); // edit class
    buf.push(0); // title (empty)
    buf.push(0); // creation data length

    // --- Control 4: Link Accounts button ---
    align4(&mut buf);
    let link_btn_style: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32;
    buf.push(link_btn_style as u16);
    buf.push((link_btn_style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(75);  // x
    buf.push(69);  // y
    buf.push(65);  // cx
    buf.push(14);  // cy
    buf.push(IDC_LINK_ACCOUNTS_BTN as u16); // id
    buf.push(0xFFFF);
    buf.push(0x0080); // button class
    for c in "Link Accounts".encode_utf16() { buf.push(c); }
    buf.push(0);
    buf.push(0); // creation data length

    // --- Control 5: Cancel button ---
    align4(&mut buf);
    let btn_style2: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32;
    buf.push(btn_style2 as u16);
    buf.push((btn_style2 >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(85);  // x
    buf.push(96);  // y
    buf.push(50);  // cx
    buf.push(14);  // cy
    buf.push(IDC_LOGIN_CANCEL as u16); // id
    buf.push(0xFFFF);
    buf.push(0x0080); // button class
    for c in "Cancel".encode_utf16() { buf.push(c); }
    buf.push(0);
    buf.push(0); // creation data length

    buf
}

/// Draws the official Microsoft branded "Sign in with Microsoft" button
unsafe fn draw_microsoft_sign_in_button(dis: &windows::Win32::UI::Controls::DRAWITEMSTRUCT) {
    let hdc = dis.hDC;
    let rc = dis.rcItem;

    // Background: white
    let bg_brush = CreateSolidBrush(COLORREF(0x00FFFFFF)); // white
    FillRect(hdc, &rc, bg_brush);
    let _ = DeleteObject(bg_brush);

    // Border: #8C8C8C
    let border_pen = CreatePen(PS_SOLID, 1, COLORREF(0x008C8C8C));
    let old_pen = SelectObject(hdc, border_pen);
    let old_brush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, old_brush);
    SelectObject(hdc, old_pen);
    let _ = DeleteObject(border_pen);

    // Microsoft logo - 4 colored squares, positioned vertically centered
    let logo_size = 4; // each square is 4x4 pixels
    let logo_gap = 1;  // 1px gap between squares
    let logo_total = logo_size * 2 + logo_gap; // 9px total
    let logo_x = rc.left + 12;
    let logo_y = rc.top + (rc.bottom - rc.top - logo_total) / 2;

    // Top-left: Red (#F25022)
    let red_brush = CreateSolidBrush(COLORREF(0x002250F2));
    let red_rc = RECT { left: logo_x, top: logo_y, right: logo_x + logo_size, bottom: logo_y + logo_size };
    FillRect(hdc, &red_rc, red_brush);
    let _ = DeleteObject(red_brush);

    // Top-right: Green (#7FBA00)
    let green_brush = CreateSolidBrush(COLORREF(0x0000BA7F));
    let green_rc = RECT { left: logo_x + logo_size + logo_gap, top: logo_y, right: logo_x + logo_total, bottom: logo_y + logo_size };
    FillRect(hdc, &green_rc, green_brush);
    let _ = DeleteObject(green_brush);

    // Bottom-left: Blue (#00A4EF)
    let blue_brush = CreateSolidBrush(COLORREF(0x00EFA400));
    let blue_rc = RECT { left: logo_x, top: logo_y + logo_size + logo_gap, right: logo_x + logo_size, bottom: logo_y + logo_total };
    FillRect(hdc, &blue_rc, blue_brush);
    let _ = DeleteObject(blue_brush);

    // Bottom-right: Yellow (#FFB900)
    let yellow_brush = CreateSolidBrush(COLORREF(0x0000B9FF));
    let yellow_rc = RECT { left: logo_x + logo_size + logo_gap, top: logo_y + logo_size + logo_gap, right: logo_x + logo_total, bottom: logo_y + logo_total };
    FillRect(hdc, &yellow_rc, yellow_brush);
    let _ = DeleteObject(yellow_brush);

    // Text: "Sign in with Microsoft" in #5E5E5E, Segoe UI Semibold
    let font = CreateFontW(
        -15, 0, 0, 0,
        FW_SEMIBOLD.0 as i32,
        0, 0, 0,
        DEFAULT_CHARSET.0 as u32,
        OUT_DEFAULT_PRECIS.0 as u32,
        CLIP_DEFAULT_PRECIS.0 as u32,
        CLEARTYPE_QUALITY.0 as u32,
        (FF_DONTCARE.0 | DEFAULT_PITCH.0) as u32,
        w!("Segoe UI"),
    );
    let old_font = SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, COLORREF(0x005E5E5E));

    let text_str = "Sign in with Microsoft";
    let mut text_wide: Vec<u16> = text_str.encode_utf16().collect();
    let mut text_rc = RECT {
        left: logo_x + logo_total + 10,
        top: rc.top,
        right: rc.right - 8,
        bottom: rc.bottom,
    };
    DrawTextW(hdc, &mut text_wide, &mut text_rc, DT_SINGLELINE | DT_VCENTER);

    SelectObject(hdc, old_font);
    let _ = DeleteObject(font);
}

/// Performs the login flow: fetches nonce (with optional link_code), runs OAuth, exchanges token
unsafe fn perform_login(hwnd: HWND, link_code: Option<String>) {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // Build nonce URL with optional link_code
    let nonce_url = match &link_code {
        Some(code) => format!("https://notes-auth-func.azurewebsites.net/api/get_nonce?link_code={}", code),
        None => "https://notes-auth-func.azurewebsites.net/api/get_nonce".to_string(),
    };
    println!("[Login] Fetching nonce from: {}", nonce_url);

    // Fetch nonce from Azure Function
    let nonce = match rt.block_on(async {
        let resp = reqwest::get(&nonce_url).await?;
        resp.text().await
    }) {
        Ok(n) => {
            println!("[Login] Received nonce: {}", n);
            n
        }
        Err(e) => {
            eprintln!("[Login] Failed to fetch nonce: {}", e);
            let msg = format!("Failed to fetch nonce:\n{}\0", e);
            let msg_wide: Vec<u16> = msg.encode_utf16().collect();
            MessageBoxW(hwnd, PCWSTR(msg_wide.as_ptr()), w!("Login Error"), MB_OK | MB_ICONERROR);
            return;
        }
    };

    println!("[Login] Starting OAuth2 flow with nonce...");
    match rt.block_on(microsoft_auth::login_with_microsoft(&nonce)) {
        Ok(token_response) => {
            println!("[Login] Successfully authenticated!");
            println!("[Login] Access token: {}...", &token_response.access_token[..20.min(token_response.access_token.len())]);
            if let Some(ref id_token) = token_response.id_token {
                println!("[Login] ID token received ({} chars)", id_token.len());
            }

            // Send the id_token to the backend to exchange for AWS credentials
            let post_token = token_response.id_token.as_deref()
                .unwrap_or(&token_response.access_token);
            println!("[Login] Sending token to get_token endpoint...");
            match rt.block_on(async {
                let client = reqwest::Client::new();
                let resp = client
                    .post("https://notes-auth-func.azurewebsites.net/api/get_token")
                    .body(post_token.to_string())
                    .send()
                    .await?;
                resp.text().await
            }) {
                Ok(refresh_token) => {
                    println!("[Login] Refresh token: {}", refresh_token);
                    save_refresh_token(&refresh_token);
                    REFRESH_TOKEN = Some(refresh_token.clone());

                    // Call get_url with the refresh token
                    match rt.block_on(call_get_url(&refresh_token)) {
                        Ok((sas_url, new_token)) => {
                            println!("[Login] Container SAS URL: {}", sas_url);
                            CONTAINER_SAS_URL = Some(sas_url);
                            if let Some(t) = new_token {
                                println!("[Login] New refresh token: {}", t);
                                save_refresh_token(&t);
                                REFRESH_TOKEN = Some(t);
                            }
                        }
                        Err(e) => {
                            eprintln!("[Login] Failed to call get_url: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[Login] Failed to send token to get_token: {}", e);
                }
            }

            let _ = EndDialog(hwnd, 1);
        }
        Err(e) => {
            eprintln!("[Login] Authentication failed: {}", e);
            let msg = format!("Authentication failed:\n{}\0", e);
            let msg_wide: Vec<u16> = msg.encode_utf16().collect();
            MessageBoxW(hwnd, PCWSTR(msg_wide.as_ptr()), w!("Login Error"), MB_OK | MB_ICONERROR);
        }
    }
}

/// Dialog procedure for the login dialog
unsafe extern "system" fn login_dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            // Set 6-character limit on the link code textbox
            let edit = GetDlgItem(hwnd, IDC_LINK_CODE_EDIT).unwrap_or_default();
            SendMessageW(edit, EM_LIMITTEXT, WPARAM(6), LPARAM(0));
            1 // TRUE - let system set focus
        }
        WM_DRAWITEM => {
            let dis = &*(lparam.0 as *const windows::Win32::UI::Controls::DRAWITEMSTRUCT);
            if dis.CtlID == IDC_LOGIN_BTN as u32 {
                draw_microsoft_sign_in_button(dis);
                return 1; // TRUE - we handled it
            }
            0
        }
        WM_COMMAND => {
            let control_id = (wparam.0 & 0xFFFF) as i32;
            if control_id == IDC_LOGIN_BTN {
                println!("[Login] Sign in with Microsoft clicked");
                perform_login(hwnd, None);
                0
            } else if control_id == IDC_LINK_ACCOUNTS_BTN {
                // Read the link code from the textbox
                let edit_hwnd = GetDlgItem(hwnd, IDC_LINK_CODE_EDIT).unwrap_or_default();
                let mut buf = [0u16; 7];
                let len = GetWindowTextW(edit_hwnd, &mut buf);
                let link_code = String::from_utf16_lossy(&buf[..len as usize]);

                if link_code.len() != 6 || !link_code.chars().all(|c| c.is_ascii_digit()) {
                    MessageBoxW(hwnd, w!("Please enter exactly 6 digits."), w!("Invalid Code"), MB_OK | MB_ICONWARNING);
                    return 0;
                }

                println!("[Login] Link Accounts clicked with code: {}", link_code);
                perform_login(hwnd, Some(link_code));
                0
            } else if control_id == IDC_LOGIN_CANCEL {
                let _ = EndDialog(hwnd, 0);
                1
            } else {
                0
            }
        }
        WM_CLOSE => {
            let _ = EndDialog(hwnd, 0);
            1
        }
        _ => 0,
    }
}

/// Shows the Azure blob picker dialog and opens the selected file in a new window
unsafe fn show_open_file_dialog() {
    if CONTAINER_SAS_URL.is_none() {
        eprintln!("[OpenFile] No Azure SAS URL configured");
        return;
    }

    // List blobs from Azure
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let keys = match list_blobs_with_retry(&rt) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("[OpenFile] Failed to list Azure blobs: {}", e);
            return;
        }
    };

    if keys.is_empty() {
        println!("[OpenFile] No blobs found in Azure container");
        return;
    }

    // Store keys for the dialog proc to read
    PICKER_KEYS = Some(keys);
    PICKER_SELECTED = None;

    // Build and show the dialog
    let template = build_picker_dialog_template();
    let result = DialogBoxIndirectParamW(
        GetModuleHandleW(None).unwrap_or_default(),
        template.as_ptr() as *const DLGTEMPLATE,
        MAIN_HWND,
        Some(picker_dlg_proc),
        LPARAM(0),
    );

    // Clean up
    PICKER_KEYS = None;

    if result <= 0 {
        println!("[OpenFile] Dialog cancelled or failed");
        return;
    }

    let selected_key = match PICKER_SELECTED.take() {
        Some(key) => key,
        None => return,
    };

    println!("[OpenFile] Selected: {}", selected_key);

    // Resolve local path: USERPROFILE/Notes/<key>
    let notes_dir = match std::env::var("USERPROFILE") {
        Ok(home) => std::path::Path::new(&home).join("Notes"),
        Err(_) => {
            eprintln!("[OpenFile] USERPROFILE not set");
            return;
        }
    };

    if !notes_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&notes_dir) {
            eprintln!("[OpenFile] Failed to create Notes directory: {}", e);
            return;
        }
    }

    let new_path = notes_dir.join(&selected_key);

    // Fetch from Azure and compare with local
    let local_exists = new_path.exists();
    let local_modified = std::fs::metadata(&new_path).ok().and_then(|m| m.modified().ok());

    let mut remote_content: Option<String> = None;
    let mut remote_modified: Option<SystemTime> = None;

    match fetch_notes_with_retry(&rt, &selected_key) {
        Ok((content, modified)) => {
            remote_content = Some(content);
            remote_modified = modified;
        }
        Err(e) => {
            eprintln!("[OpenFile] Failed to fetch Azure content: {}", e);
        }
    }

    match (local_exists, remote_content.is_some()) {
        (false, false) => {
            println!("[OpenFile] Neither local nor remote content available");
            return;
        }
        (true, false) => {
            println!("[OpenFile] Using existing local file");
        }
        (false, true) => {
            println!("[OpenFile] Downloading from Azure");
            if let Some(content) = &remote_content {
                if let Err(e) = std::fs::write(&new_path, content) {
                    eprintln!("[OpenFile] Failed to save remote content locally: {}", e);
                }
            }
        }
        (true, true) => {
            match (remote_modified, local_modified) {
                (Some(remote_time), Some(local_time)) if remote_time > local_time => {
                    println!("[OpenFile] Remote is newer, overwriting local file");
                    if let Some(content) = &remote_content {
                        if let Err(e) = std::fs::write(&new_path, content) {
                            eprintln!("[OpenFile] Failed to overwrite local file: {}", e);
                        }
                    }
                }
                _ => {
                    println!("[OpenFile] Local file is newer or same age, using local");
                }
            }
        }
    }

    // Spawn a new instance for the selected file
    let exe_path = std::env::current_exe().expect("Failed to get current exe path");
    let mut cmd = std::process::Command::new(&exe_path);
    cmd.arg(&new_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    // Pass SAS URL and refresh token to the child process
    if let Some(ref sas) = CONTAINER_SAS_URL {
        cmd.env("NOTES_SAS_URL", sas);
    }
    if let Some(ref token) = REFRESH_TOKEN {
        cmd.env("NOTES_REFRESH_TOKEN", token);
    }
    match cmd.spawn() {
        Ok(_) => println!("[OpenFile] Spawned new window for {:?}", new_path),
        Err(e) => eprintln!("[OpenFile] Failed to spawn new window: {}", e),
    }
}
