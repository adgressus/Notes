// #![windows_subsystem = "windows"]  // Commented out for debugging

use std::mem::zeroed;
use std::path::PathBuf;
use std::time::SystemTime;
use aws_sdk_s3::Client;
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Graphics::Gdi::*,
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

/// Fetches notes.txt from S3 directly using the SDK
/// Returns the content and the last modified timestamp
async fn fetch_notes_from_s3(bucket: &str, key: &str) -> std::result::Result<(String, Option<SystemTime>), Box<dyn std::error::Error + Send + Sync>> {
    println!("[S3] Loading AWS config from environment...");
    let config = aws_config::load_from_env().await;
    println!("[S3] AWS config loaded. Region: {:?}", config.region());
    
    let client = Client::new(&config);
    println!("[S3] S3 client created");

    println!("[S3] Fetching object from bucket='{}', key='{}'", bucket, key);
    let response = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await?;

    // Get the last modified timestamp from S3
    let s3_last_modified = response.last_modified().and_then(|dt| {
        let secs = dt.secs();
        let nanos = dt.subsec_nanos();
        SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::new(secs as u64, nanos))
    });
    println!("[S3] S3 last modified: {:?}", s3_last_modified);

    println!("[S3] Response received, reading body...");
    let bytes = response.body.collect().await?.into_bytes();
    let content = String::from_utf8_lossy(&bytes).to_string();
    println!("[S3] Content fetched successfully, {} bytes", content.len());
    
    Ok((content, s3_last_modified))
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

/// Lists all keys in the S3 bucket
async fn list_s3_keys(bucket: &str) -> std::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    println!("[S3 List] Loading AWS config...");
    let config = aws_config::load_from_env().await;
    let client = Client::new(&config);

    let mut keys = Vec::new();
    let mut continuation_token: Option<String> = None;

    loop {
        let mut request = client.list_objects_v2().bucket(bucket);
        if let Some(token) = &continuation_token {
            request = request.continuation_token(token);
        }

        let response = request.send().await?;

        for obj in response.contents() {
            if let Some(key) = obj.key() {
                keys.push(key.to_string());
            }
        }

        if response.is_truncated() == Some(true) {
            continuation_token = response.next_continuation_token().map(|s| s.to_string());
        } else {
            break;
        }
    }

    println!("[S3 List] Found {} keys", keys.len());
    Ok(keys)
}

/// Uploads content to S3 bucket
async fn upload_notes_to_s3(bucket: &str, key: &str, content: &str) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("[S3 Upload] Loading AWS config from environment...");
    let config = aws_config::load_from_env().await;
    
    let client = Client::new(&config);
    println!("[S3 Upload] Uploading to bucket='{}', key='{}'", bucket, key);
    
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(aws_sdk_s3::primitives::ByteStream::from(content.as_bytes().to_vec()))
        .send()
        .await?;
    
    println!("[S3 Upload] Upload successful");
    Ok(())
}

fn main() -> Result<()> {
    // Get bucket name from environment variable
    let bucket = std::env::var("S3_BUCKET").unwrap_or_default();
    
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
    println!("[Main] S3_BUCKET env var: '{}'", bucket);
    println!("[Main] AWS_REGION env var: '{}'", std::env::var("AWS_REGION").unwrap_or_default());
    println!("[Main] AWS_ACCESS_KEY_ID env var: '{}'", 
        std::env::var("AWS_ACCESS_KEY_ID").map(|s| format!("{}...", &s[..4.min(s.len())])).unwrap_or_default());
    
    // If AWS credentials are not set, show login dialog
    let aws_key = std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
    if aws_key.is_empty() {
        println!("[Main] AWS_ACCESS_KEY_ID not set, showing login dialog");
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

    // Fetch content from S3 in a blocking manner before starting the GUI
    if !bucket.is_empty() {
        println!("[Main] Creating Tokio runtime...");
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        println!("[Main] Fetching notes from S3...");
        match rt.block_on(fetch_notes_from_s3(&bucket, &file_name)) {
            Ok((s3_content, s3_modified)) => {
                println!("[Main] Successfully fetched {} bytes from S3", s3_content.len());
                
                // Compare timestamps to decide which source to use
                let local_modified = get_local_file_modified_time();
                println!("[Main] Local file last modified: {:?}", local_modified);
                
                let use_s3 = match (s3_modified, local_modified) {
                    (Some(s3_time), Some(local_time)) => {
                        if s3_time > local_time {
                            println!("[Main] S3 is newer, using S3 content and overwriting local file");
                            // Overwrite local file with S3 content
                            if let Some(path) = get_notes_path() {
                                if let Err(e) = std::fs::write(&path, &s3_content) {
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
                        println!("[Main] No local file exists, using S3 content");
                        // Save S3 content to local file
                        if let Some(path) = get_notes_path() {
                            if let Err(e) = std::fs::write(&path, &s3_content) {
                                eprintln!("[Main] Failed to save S3 content to local file: {}", e);
                            }
                        }
                        true
                    }
                    _ => {
                        println!("[Main] Could not determine S3 timestamp, using S3 content");
                        true
                    }
                };
                
                let content = if use_s3 {
                    s3_content
                } else {
                    read_local_notes().unwrap_or(s3_content)
                };
                
                unsafe { INITIAL_CONTENT = Some(content); }
            }
            Err(e) => {
                eprintln!("[Main] ERROR: Failed to fetch notes from S3: {}", e);
                // Fall back to local file if S3 fails
                if let Some(content) = read_local_notes() {
                    println!("[Main] Falling back to local file");
                    unsafe { INITIAL_CONTENT = Some(content); }
                }
            }
        }
    } else {
        println!("[Main] S3_BUCKET is empty, reading local file only");
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
                    
                    // Upload to S3 if bucket is configured
                    let bucket = std::env::var("S3_BUCKET").unwrap_or_default();
                    if !bucket.is_empty() {
                        let key = get_current_key();
                        println!("[Save] Uploading to S3 with key '{}'...", key);
                        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
                        match rt.block_on(upload_notes_to_s3(&bucket, &key, &text)) {
                            Ok(_) => println!("[Save] Successfully uploaded to S3"),
                            Err(e) => eprintln!("[Save] Failed to upload to S3: {}", e),
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
    
    // Upload to S3 if configured
    let bucket = std::env::var("S3_BUCKET").unwrap_or_default();
    if !bucket.is_empty() {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        if let Err(e) = rt.block_on(upload_notes_to_s3(&bucket, &new_filename, &text)) {
            eprintln!("[SaveAs] S3 upload failed: {}", e);
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
    
    // Check S3 for existing file
    let bucket = std::env::var("S3_BUCKET").unwrap_or_default();
    let mut s3_content: Option<String> = None;
    let mut s3_modified: Option<SystemTime> = None;
    
    if !bucket.is_empty() {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        match rt.block_on(fetch_notes_from_s3(&bucket, &new_filename)) {
            Ok((content, modified)) => {
                s3_content = Some(content);
                s3_modified = modified;
                println!("[NewFile] Found S3 file, modified: {:?}", s3_modified);
            }
            Err(e) => {
                println!("[NewFile] No S3 file found or error: {}", e);
            }
        }
    }
    
    // Determine what to do based on existence and timestamps
    match (local_exists, s3_content.is_some()) {
        (false, false) => {
            // Neither exists - create new empty file locally and in S3
            println!("[NewFile] Creating new empty file");
            if let Err(e) = std::fs::write(&new_path, "") {
                eprintln!("[NewFile] Failed to create file: {}", e);
                return;
            }
            if !bucket.is_empty() {
                let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
                if let Err(e) = rt.block_on(upload_notes_to_s3(&bucket, &new_filename, "")) {
                    eprintln!("[NewFile] S3 upload failed: {}", e);
                }
            }
        }
        (true, false) => {
            // Local exists, no S3 - use local as-is
            println!("[NewFile] Using existing local file (no S3 version)");
        }
        (false, true) => {
            // S3 exists, no local - download from S3
            println!("[NewFile] Downloading from S3 (no local file)");
            if let Some(content) = &s3_content {
                if let Err(e) = std::fs::write(&new_path, content) {
                    eprintln!("[NewFile] Failed to save S3 content locally: {}", e);
                }
            }
        }
        (true, true) => {
            // Both exist - compare timestamps
            match (s3_modified, local_modified) {
                (Some(s3_time), Some(local_time)) if s3_time > local_time => {
                    println!("[NewFile] S3 is newer, overwriting local file");
                    if let Some(content) = &s3_content {
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
    match std::process::Command::new(&exe_path)
        .arg(&new_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
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
    buf.push(3); // cdit - number of controls (static text, login button, cancel button)
    buf.push(80);  // x
    buf.push(80);  // y
    buf.push(220); // cx
    buf.push(90);  // cy
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

    // --- Control 3: Cancel button ---
    align4(&mut buf);
    let btn_style2: u32 = WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32;
    buf.push(btn_style2 as u16);
    buf.push((btn_style2 >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(85);  // x
    buf.push(68);  // y
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

/// Dialog procedure for the login dialog
unsafe extern "system" fn login_dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
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
                println!("[Login] Sign in with Microsoft clicked, starting OAuth2 flow...");
                let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
                match rt.block_on(microsoft_auth::login_with_microsoft()) {
                    Ok(token_response) => {
                        println!("[Login] Successfully authenticated!");
                        println!("[Login] Access token: {}...", &token_response.access_token[..20.min(token_response.access_token.len())]);
                        if let Some(ref id_token) = token_response.id_token {
                            println!("[Login] ID token received ({} chars)", id_token.len());
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

/// Shows the S3 file picker dialog and opens the selected file in a new window
unsafe fn show_open_file_dialog() {
    let bucket = std::env::var("S3_BUCKET").unwrap_or_default();
    if bucket.is_empty() {
        eprintln!("[OpenFile] S3_BUCKET not configured");
        return;
    }

    // List keys from S3
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let keys = match rt.block_on(list_s3_keys(&bucket)) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("[OpenFile] Failed to list S3 keys: {}", e);
            return;
        }
    };

    if keys.is_empty() {
        println!("[OpenFile] No files found in S3 bucket");
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

    // Fetch from S3 and compare with local (same pattern as show_new_file_dialog)
    let local_exists = new_path.exists();
    let local_modified = std::fs::metadata(&new_path).ok().and_then(|m| m.modified().ok());

    let mut s3_content: Option<String> = None;
    let mut s3_modified: Option<SystemTime> = None;

    match rt.block_on(fetch_notes_from_s3(&bucket, &selected_key)) {
        Ok((content, modified)) => {
            s3_content = Some(content);
            s3_modified = modified;
        }
        Err(e) => {
            eprintln!("[OpenFile] Failed to fetch S3 content: {}", e);
        }
    }

    match (local_exists, s3_content.is_some()) {
        (false, false) => {
            println!("[OpenFile] Neither local nor S3 content available");
            return;
        }
        (true, false) => {
            println!("[OpenFile] Using existing local file");
        }
        (false, true) => {
            println!("[OpenFile] Downloading from S3");
            if let Some(content) = &s3_content {
                if let Err(e) = std::fs::write(&new_path, content) {
                    eprintln!("[OpenFile] Failed to save S3 content locally: {}", e);
                }
            }
        }
        (true, true) => {
            match (s3_modified, local_modified) {
                (Some(s3_time), Some(local_time)) if s3_time > local_time => {
                    println!("[OpenFile] S3 is newer, overwriting local file");
                    if let Some(content) = &s3_content {
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
    match std::process::Command::new(&exe_path)
        .arg(&new_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
        Ok(_) => println!("[OpenFile] Spawned new window for {:?}", new_path),
        Err(e) => eprintln!("[OpenFile] Failed to spawn new window: {}", e),
    }
}
