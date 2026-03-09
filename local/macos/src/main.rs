#![deny(unsafe_op_in_unsafe_fn)]
use std::cell::OnceCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, sel, AnyThread, DefinedClass, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate,
    NSAutoresizingMaskOptions, NSBackingStoreType, NSTextView, NSScrollView, NSBorderType, NSWindow,
    NSWindowDelegate, NSWindowStyleMask, NSSavePanel, NSMenu, NSMenuItem,
    NSEventModifierFlags, NSPanel, NSButton, NSBezelStyle, NSTableView, NSTableColumn,
    NSSearchField, NSTableViewDelegate, NSTableViewDataSource, NSSearchFieldDelegate,
    NSControlTextEditingDelegate, NSTextFieldDelegate, NSControl,
};
use objc2_authentication_services::{
    ASAuthorizationAppleIDButton, ASAuthorizationAppleIDButtonStyle, ASAuthorizationAppleIDButtonType,
    ASAuthorizationAppleIDProvider, ASAuthorizationAppleIDCredential,
    ASAuthorizationController, ASAuthorizationControllerDelegate,
    ASAuthorization,
};
use objc2_foundation::{
    ns_string, MainThreadMarker, NSNotification, NSObject, NSObjectProtocol, NSPoint, NSRect,
    NSSize, NSString, NSUserDefaults, NSDictionary, NSNumber, NSMutableArray, NSArray, NSURL,
    NSInteger, NSTimer, NSError, NSCopying,
};

// HTTP
use std::time::SystemTime;

#[derive(Debug, Clone)]
struct WindowState {
    file_path: PathBuf,
    frame_x: f64,
    frame_y: f64,
    frame_width: f64,
    frame_height: f64,
}

impl WindowState {
    fn to_dict(&self, _mtm: MainThreadMarker) -> Retained<NSDictionary<NSString, NSObject>> {
        let path_str = self.file_path.to_string_lossy();
        let ns_path = NSString::from_str(&path_str);
        let x_num = NSNumber::new_f64(self.frame_x);
        let y_num = NSNumber::new_f64(self.frame_y);
        let w_num = NSNumber::new_f64(self.frame_width);
        let h_num = NSNumber::new_f64(self.frame_height);
        
        let keys: &[&NSString] = &[
            ns_string!("filePath"),
            ns_string!("frameX"),
            ns_string!("frameY"),
            ns_string!("frameWidth"),
            ns_string!("frameHeight"),
        ];
        
        // Cast values to &NSObject for the dictionary
        let values: &[&NSObject] = &[
            &ns_path,
            &x_num,
            &y_num,
            &w_num,
            &h_num,
        ];
        
        NSDictionary::from_slices(keys, values)
    }
    
    fn from_dict(dict: &NSDictionary<NSString, NSObject>) -> Option<Self> {
        // Helper to extract f64 from dictionary
        fn get_f64(dict: &NSDictionary<NSString, NSObject>, key: &NSString) -> Option<f64> {
            let obj = dict.objectForKey(key)?;
            let num = Retained::downcast::<NSNumber>(obj).ok()?;
            Some(num.as_f64())
        }

        // Extract file_path (required)
        let file_path: PathBuf = {
            let obj = dict.objectForKey(ns_string!("filePath"))?;
            let nsstring = Retained::downcast::<NSString>(obj).ok()?;
            PathBuf::from(nsstring.to_string())
        };

        // Extract frame values
        let frame_x = get_f64(dict, ns_string!("frameX"))?;
        let frame_y = get_f64(dict, ns_string!("frameY"))?;
        let frame_width = get_f64(dict, ns_string!("frameWidth"))?;
        let frame_height = get_f64(dict, ns_string!("frameHeight"))?;

        Some(WindowState {
            file_path,
            frame_x,
            frame_y,
            frame_width,
            frame_height,
        })
    }
}

fn save_window_states(mtm: MainThreadMarker) {
    let app = NSApplication::sharedApplication(mtm);
    let windows = app.windows();
    log::info!("NSApplication windows count: {}", windows.count());
    
    // Debug: print info about each window
    for (i, window) in windows.iter().enumerate() {
        let title_rust = window.title().to_string();
        let is_visible = window.isVisible();
        let has_delegate = window.delegate().is_some();
        log::info!("  Window {}: title='{}', visible={}, has_delegate={}", 
            i, title_rust, is_visible, has_delegate);
    }
    
    // Create fresh array (replace mode - don't append to existing)
    let array = NSMutableArray::<NSDictionary<NSString, NSObject>>::new();
    let mut count = 0usize;
    
    for window in windows.iter() {
        // Get delegate and try to downcast to our WindowDelegate type
        let Some(delegate_proto) = window.delegate() else {
            continue;
        };
        
        // Use Retained::downcast to safely check if it's our WindowDelegate
        let delegate_obj: Retained<NSObject> = unsafe { 
            Retained::cast_unchecked(delegate_proto) 
        };
        let Ok(delegate) = Retained::downcast::<WindowDelegate>(delegate_obj) else {
            continue;
        };
        
        let frame = window.frame();
        
        // Get file path (skip windows without a file)
        let file_path = match delegate.ivars().current_file.lock().unwrap().clone() {
            Some(p) => p,
            None => continue,
        };
        
        let state = WindowState {
            file_path,
            frame_x: frame.origin.x,
            frame_y: frame.origin.y,
            frame_width: frame.size.width,
            frame_height: frame.size.height,
        };
        
        let dict = state.to_dict(mtm);
        array.addObject(&dict);
        count += 1;
    }
    
    // Don't overwrite existing states if we have nothing to save
    if count == 0 {
        log::info!("No window states to save, preserving existing states");
        return;
    }
    
    let defaults = NSUserDefaults::standardUserDefaults();
    // Safety: array is a valid NSMutableArray containing NSDictionary objects
    unsafe {
        defaults.setObject_forKey(Some(&array), ns_string!("windowStates"));
    }
    
    log::info!("Saved {} window states", count);
}

fn load_window_states(_mtm: MainThreadMarker) -> Vec<WindowState> {
    let defaults = NSUserDefaults::standardUserDefaults();
    
    // Get the array from user defaults
    let Some(obj) = defaults.objectForKey(ns_string!("windowStates")) else {
        return Vec::new();
    };
    
    // Downcast to NSArray (non-generic)
    let Ok(array) = Retained::downcast::<NSArray>(obj) else {
        return Vec::new();
    };
    
    let mut states = Vec::new();
    
    for i in 0..array.count() {
        let dict_obj = array.objectAtIndex(i);
        // Downcast to NSDictionary (non-generic)
        if let Ok(dict) = Retained::downcast::<NSDictionary>(dict_obj) {
            // Cast to the typed version - safe because we control what goes into the dictionary
            let typed_dict: &NSDictionary<NSString, NSObject> = unsafe { 
                &*((&*dict) as *const NSDictionary as *const NSDictionary<NSString, NSObject>)
            };
            if let Some(state) = WindowState::from_dict(typed_dict) {
                states.push(state);
            }
        }
    }
    
    // Clear the stored states after loading (they'll be re-saved when windows close)
    defaults.removeObjectForKey(ns_string!("windowStates"));
    
    log::info!("Loaded {} window states (cleared from storage)", states.len());
    states
}

/// Generates a unique filename in ~/Notes/ with format "Month Day, Hour AM/PM (Year).txt"
/// If a file with that name exists, appends -1, -2, etc. until unique.
fn generate_unique_dated_filepath() -> PathBuf {
    use chrono::Local;
    
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let notes_dir = PathBuf::from(&home).join("Notes");
    
    // Create ~/Notes/ if it doesn't exist
    if !notes_dir.exists() {
        let _ = std::fs::create_dir_all(&notes_dir);
    }
    
    let now = Local::now();
    // Format: "February 4, 3 PM (2026)"
    let base_name = now.format("%B %-d, %-I %p (%Y)").to_string();
    
    // Try the base name first
    let mut candidate = notes_dir.join(format!("{}.txt", base_name));
    if !candidate.exists() {
        return candidate;
    }
    
    // Append -1, -2, etc. until we find a unique name
    let mut suffix = 1;
    loop {
        candidate = notes_dir.join(format!("{}-{}.txt", base_name, suffix));
        if !candidate.exists() {
            return candidate;
        }
        suffix += 1;
    }
}

/// Creates a new window with the given parameters.
/// 
/// # Arguments
/// * `mtm` - Main thread marker
/// * `filename` - Filename (e.g., "notes.txt") or full path. If not absolute, resolves to ~/Notes/{filename}
/// * `frame` - Optional frame rect. If None, window is centered with default size
fn create_window(
    mtm: MainThreadMarker,
    filename: &str,
    frame: Option<NSRect>,
) {
    let file_path = if std::path::Path::new(filename).is_absolute() {
        PathBuf::from(filename)
    } else if let Ok(home) = std::env::var("HOME") {
        let mut path = PathBuf::from(home);
        path.push("Notes");
        path.push(filename);
        path
    } else {
        PathBuf::from(filename)
    };
    
    let container_sas_url = get_container_sas_url(mtm);
    let file_content = load_file_content(&file_path, container_sas_url.as_deref());
    
    let default_frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(600.0, 500.0));
    let window_frame = frame.unwrap_or(default_frame);
    let content_size = window_frame.size;
    
    let delegate = WindowDelegate::new(mtm);
    
    let tv = NSTextView::initWithFrame(
        NSTextView::alloc(mtm),
        NSRect::new(NSPoint::new(0.0, 0.0), content_size));
    if let Some(ref s) = file_content {
        tv.setString(&NSString::from_str(s.as_str()));
    }
    tv.setEditable(true);
    tv.setAllowsUndo(true);
    tv.setAutoresizingMask(
        NSAutoresizingMaskOptions::ViewWidthSizable | NSAutoresizingMaskOptions::ViewHeightSizable);
    
    let scroll_view = NSScrollView::initWithFrame(
        NSScrollView::alloc(mtm),
        NSRect::new(NSPoint::new(0.0, 0.0), content_size));
    scroll_view.setHasVerticalScroller(true);
    scroll_view.setHasHorizontalScroller(false);
    scroll_view.setBorderType(NSBorderType::GrooveBorder);
    scroll_view.setDocumentView(Some(&*tv));
    scroll_view.setAutoresizingMask(
        NSAutoresizingMaskOptions::ViewWidthSizable | NSAutoresizingMaskOptions::ViewHeightSizable);
    
    // Safety: Valid frame, style mask, backing store type, and window is properly initialized
    let window = unsafe {
        let win = NSWindow::initWithContentRect_styleMask_backing_defer(
            NSWindow::alloc(mtm),
            window_frame,
            NSWindowStyleMask::Titled | NSWindowStyleMask::Closable | NSWindowStyleMask::Miniaturizable | NSWindowStyleMask::Resizable,
            NSBackingStoreType::Buffered, false);
        win.setReleasedWhenClosed(false);
        win
    };
    window.setTitle(ns_string!("Notes"));
    window.contentView().expect("window must have content view").addSubview(&scroll_view);
    window.setContentMinSize(NSSize::new(300.0, 300.0));
    if frame.is_none() { window.center(); }
    
    delegate.ivars().text_view.set(tv.clone()).ok();
    *delegate.ivars().current_file.lock().unwrap() = Some(file_path);
    // Initialize hash for change detection
    let initial_content = file_content.as_deref().unwrap_or("");
    *delegate.ivars().last_saved_hash.lock().unwrap() = compute_content_hash(initial_content);
    window.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    //Store strong self-reference to keep delegate alive until window closes
    let ptr = &*delegate as *const WindowDelegate as *mut WindowDelegate;
    *delegate.ivars().self_ref.lock().unwrap() = Some(unsafe { Retained::retain(ptr).unwrap() });
    window.makeKeyAndOrderFront(None);
}

fn create_window_from_state(state: WindowState, mtm: MainThreadMarker) {
    let filename = state.file_path.to_string_lossy().into_owned();
    
    let frame = NSRect::new(
        NSPoint::new(state.frame_x, state.frame_y),
        NSSize::new(state.frame_width, state.frame_height)
    );
    
    create_window(mtm, &filename, Some(frame));
}

fn print_error_chain(err: &dyn std::error::Error) {
    log::error!("error: {}", err);
    let mut src = err.source();
    while let Some(s) = src {
        log::error!("caused by: {}", s);
        src = s.source();
    }
}

/// Compute a hash of the content for change detection.
fn compute_content_hash(content: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}

/// Auto-save all open windows that have unsaved changes.
/// Called periodically by NSTimer.
fn auto_save_all_windows(mtm: MainThreadMarker) {
    let app = NSApplication::sharedApplication(mtm);
    let windows = app.windows();
    
    log::debug!(" auto_save_all_windows: checking {} windows", windows.count());
    
    for window in windows.iter() {
        // Get delegate and try to downcast to our WindowDelegate type
        let Some(delegate_proto) = window.delegate() else { continue };
        let delegate_obj: Retained<NSObject> = unsafe { Retained::cast_unchecked(delegate_proto) };
        let Ok(delegate) = Retained::downcast::<WindowDelegate>(delegate_obj) else { continue };
        
        // Get text view and file path
        let Some(text_view) = delegate.ivars().text_view.get() else { continue };
        let Some(file_path) = delegate.ivars().current_file.lock().unwrap().clone() else { continue };
        
        let content = text_view.string().to_string();
        let current_hash = compute_content_hash(&content);
        let last_hash = *delegate.ivars().last_saved_hash.lock().unwrap();
        
        // Skip if content hasn't changed
        if current_hash == last_hash {
            log::debug!(" auto_save: no changes in {} (hash match)", file_path.display());
            continue;
        }
        
        log::info!("Auto-save: changes detected in {}", file_path.display());
        
        // Save locally
        match std::fs::write(&file_path, &content) {
            Ok(_) => log::info!("Auto-save: wrote to {}", file_path.display()),
            Err(e) => {
                log::error!("Auto-save: failed to write {}: {}", file_path.display(), e);
                continue;
            }
        }
        
        // Upload to Azure if configured
        if let Some(sas_url) = get_container_sas_url(mtm) {
            let key = file_path.file_name()
                .and_then(|os| os.to_str())
                .unwrap_or("notes.txt")
                .to_string();
            
            match azure_upload(&sas_url, &key, content.clone().into_bytes()) {
                Ok(_) => {
                    log::info!("Auto-save: Azure upload succeeded for {}", key);
                }
                Err(e) => {
                    log::error!("Auto-save: Azure upload failed: {:?}", e);
                    // Fallback: try to refresh the SAS URL
                    if let Some(app_del) = get_app_delegate(mtm) {
                        if let Some(ref token) = *app_del.ivars().refresh_token.lock().unwrap() {
                            log::info!("Auto-save: Attempting to refresh SAS URL...");
                            match call_get_url(token) {
                                Ok((new_token, new_url)) => {
                                    *app_del.ivars().refresh_token.lock().unwrap() = Some(new_token);
                                    *app_del.ivars().container_sas_url.lock().unwrap() = Some(new_url.clone());
                                    // Retry upload with new URL
                                    if let Err(e2) = azure_upload(&new_url, &key, content.clone().into_bytes()) {
                                        log::error!("Auto-save: Retry after URL refresh also failed: {:?}", e2);
                                    } else {
                                        log::info!("Auto-save: Retry after URL refresh succeeded for {}", key);
                                    }
                                }
                                Err(e2) => {
                                    log::error!("Auto-save: Failed to refresh SAS URL: {:?}", e2);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Update hash
        *delegate.ivars().last_saved_hash.lock().unwrap() = current_hash;
    }
}

// --- Azure Blob Storage Helper Functions ---
// These functions use a container SAS URL for authentication.

const AUTH_BASE_URL: &str = "https://notes-auth-func.azurewebsites.net/api";

/// Builds the full blob URL from the container SAS URL and a blob name
fn build_blob_url(container_sas_url: &str, blob_name: &str) -> String {
    if let Some(query_start) = container_sas_url.find('?') {
        let base = &container_sas_url[..query_start];
        let query = &container_sas_url[query_start..];
        format!("{}/{}{}", base.trim_end_matches('/'), blob_name, query)
    } else {
        format!("{}/{}", container_sas_url.trim_end_matches('/'), blob_name)
    }
}

/// Builds the list blobs URL from the container SAS URL
fn build_list_url(container_sas_url: &str) -> String {
    if let Some(query_start) = container_sas_url.find('?') {
        let base = &container_sas_url[..query_start];
        let query = &container_sas_url[query_start + 1..];
        format!("{}?restype=container&comp=list&{}", base, query)
    } else {
        format!("{}?restype=container&comp=list", container_sas_url)
    }
}

/// Fetches a blob from Azure Blob Storage using the container SAS URL
fn azure_download(container_sas_url: &str, blob_name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);
    log::info!("[Azure] Fetching blob '{}'", blob_name);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
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

        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    })
}

/// Uploads content to Azure Blob Storage using the container SAS URL
fn azure_upload(container_sas_url: &str, blob_name: &str, body: Vec<u8>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);
    log::info!("[Azure Upload] Uploading blob '{}'", blob_name);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
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
            return Err(format!("Azure upload failed ({}): {}", status, body).into());
        }

        log::info!("[Azure Upload] Upload successful");
        Ok(())
    })
}

/// Gets the last modified time of an Azure blob
fn azure_last_modified(container_sas_url: &str, blob_name: &str) -> Result<Option<SystemTime>, Box<dyn std::error::Error + Send + Sync>> {
    let blob_url = build_blob_url(container_sas_url, blob_name);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = reqwest::Client::new();
        let response = client.head(&blob_url)
            .header("x-ms-version", "2020-10-02")
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let last_modified = response.headers().get("Last-Modified")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| httpdate::parse_http_date(s).ok());

        Ok(last_modified)
    })
}

/// Lists all blob names in the Azure container
fn azure_list_keys(container_sas_url: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let list_url = build_list_url(container_sas_url);
    log::info!("[Azure List] Listing blobs...");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
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
        let mut names = Vec::new();
        for segment in body.split("<Name>") {
            if let Some(end) = segment.find("</Name>") {
                names.push(segment[..end].to_string());
            }
        }
        names.sort();
        log::info!("[Azure List] Found {} blobs", names.len());
        Ok(names)
    })
}

/// Calls get_url with the refresh token, returns (new_refresh_token, container_sas_url)
fn call_get_url(refresh_token: &str) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/get_url", AUTH_BASE_URL))
            .body(refresh_token.to_string())
            .send()
            .await?;
        let body = resp.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let new_token = json.get("refresh_token")
            .and_then(|v| v.as_str())
            .ok_or("Missing refresh_token in get_url response")?
            .to_string();
        let url = json.get("url")
            .and_then(|v| v.as_str())
            .ok_or("Missing url in get_url response")?
            .to_string();
        Ok((new_token, url))
    })
}

// Load file content from either Azure Blob or local filesystem, preferring whichever is newer.
fn load_file_content(path: &PathBuf, container_sas_url: Option<&str>) -> Option<String> {
    let mut file_content: Option<String> = None;

    let local_mtime: Option<SystemTime> = match std::fs::metadata(path) {
        Ok(md) => md.modified().ok(),
        Err(_) => None,
    };

    if let Some(sas_url) = container_sas_url {
        let key = path
            .file_name()
            .and_then(|os| os.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| String::from("notes.txt"));

        match azure_last_modified(sas_url, &key) {
            Ok(blob_mtime) => {
                let should_use_remote = match (blob_mtime, local_mtime) {
                    (Some(bm), Some(lm)) => bm > lm,
                    (Some(_), None) => true,
                    _ => false,
                };

                if should_use_remote {
                    match azure_download(sas_url, &key) {
                        Ok(bytes) => {
                            if let Err(e) = std::fs::write(path, &bytes) {
                                log::error!("Failed to write Azure blob to {}: {}", path.display(), e);
                            } else if let Ok(s) = String::from_utf8(bytes) {
                                file_content = Some(s);
                                log::info!("Loaded from Azure: {} -> {}", key, path.display());
                            }
                        }
                        Err(e) => {
                            log::error!("Azure blob download error for {}: {:?}", key, e);
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("Azure HEAD error: {:?}; will fall back to local file", e);
            }
        }
    }

    if file_content.is_none() {
        if let Ok(s) = std::fs::read_to_string(path) {
            file_content = Some(s);
            log::info!("Loaded from local file: {}", path.display());
        }
    }

    file_content
}


#[derive(Default)]
struct WindowDelegateIvars {
    text_view: OnceCell<Retained<NSTextView>>,
    current_file: Mutex<Option<PathBuf>>,
    self_ref: Mutex<Option<Retained<WindowDelegate>>>,
    last_saved_hash: Mutex<u64>,
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = WindowDelegateIvars]
    struct WindowDelegate;

    unsafe impl NSObjectProtocol for WindowDelegate {}

    unsafe impl NSWindowDelegate for WindowDelegate {
        #[unsafe(method(windowWillClose:))]
        fn window_will_close(&self, notification: &NSNotification) {

            let Some(text_view) = self.ivars().text_view.get() else { return };
            let Some(file_path) = self.ivars().current_file.lock().unwrap().clone() else { return };
            
            let content = text_view.string().to_string();
            
            match std::fs::write(&file_path, &content) {
                Ok(_) => log::info!("Wrote notes to {}", file_path.display()),
                Err(e) => log::error!("Failed to write notes to {}: {}", file_path.display(), e),
            }

            // Upload to Azure if configured
            if let Some(sas_url) = get_container_sas_url(self.mtm()) {
                let key = file_path.file_name()
                    .and_then(|os| os.to_str())
                    .unwrap_or("notes.txt")
                    .to_string();
                log::info!("Azure upload: {} ({} bytes)", key, content.len());
                
                match azure_upload(&sas_url, &key, content.clone().into_bytes()) {
                    Ok(_) => log::info!("Azure upload succeeded for {}", key),
                    Err(e) => {
                        log::error!("Azure upload failed: {:?}", e);
                        print_error_chain(&*e);
                    }
                }
            }
            
            // Update hash after save
            *self.ivars().last_saved_hash.lock().unwrap() = compute_content_hash(&content);
            
            // Skip window state saving if app is terminating (save_window_states handles all windows)
            let mtm = self.mtm();
            if is_app_terminating(mtm) {
                // Drop self-reference to allow deallocation
                *self.ivars().self_ref.lock().unwrap() = None;
                return;
            }
            
            // Get window from notification object
            let Some(window_obj) = notification.object() else { return };
            let Ok(window) = Retained::downcast::<NSWindow>(window_obj) else { return };
            
            // Save this window's state, replacing any previously saved state
            let frame = window.frame();
            
            let state = WindowState {
                file_path,
                frame_x: frame.origin.x,
                frame_y: frame.origin.y,
                frame_width: frame.size.width,
                frame_height: frame.size.height,
            };
            
            let array = NSMutableArray::<NSDictionary<NSString, NSObject>>::new();
            let dict = state.to_dict(mtm);
            array.addObject(&dict);
            
            let defaults = NSUserDefaults::standardUserDefaults();
            unsafe { defaults.setObject_forKey(Some(&array), ns_string!("windowStates")) };
            
            log::info!("Saved window state (replacing previous)");

            // Drop self-reference to allow deallocation
            *self.ivars().self_ref.lock().unwrap() = None;
        }
    }

    impl WindowDelegate {
        #[unsafe(method(saveAs:))]
        fn save_as(&self, _sender: *mut objc2::runtime::AnyObject) {
            let mtm = self.mtm();
            let panel = NSSavePanel::savePanel(mtm);

            // If we have an existing current file, set the panel's directory to its parent
            {
                let guard = self.ivars().current_file.lock().unwrap();
                if let Some(ref p) = *guard {
                    if let Some(parent) = p.parent() {
                        let ns_path = NSString::from_str(&parent.to_string_lossy());
                        let url = NSURL::fileURLWithPath(&ns_path);
                        panel.setDirectoryURL(Some(&url));
                    }
                }
            }

            let result = panel.runModal();
            if result == 1 {
                if let Some(url) = panel.URL() {
                    if let Some(path_ns) = url.path() {
                        let chosen = path_ns.to_string();

                        // Update ivar current_file
                        *self.ivars().current_file.lock().unwrap() = Some(PathBuf::from(&chosen));

                        // Immediately write the current text to the chosen path and upload
                        if let Some(text_view) = self.ivars().text_view.get() {
                            let s = text_view.string().to_string();
                            if let Err(e) = std::fs::write(&chosen, &s) {
                                log::error!("Failed to write file {}: {}", chosen, e);
                            } else {
                                log::info!("Wrote notes to {}", chosen);
                            }

                            if let Some(sas_url) = get_container_sas_url(self.mtm()) {
                                // Derive key from file basename
                                let key = std::path::Path::new(&chosen)
                                    .file_name()
                                    .and_then(|os| os.to_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| String::from("notes.txt"));

                                log::info!("Azure upload requested: key='{}' size={} bytes", key, s.len());
                                
                                match azure_upload(&sas_url, &key, s.clone().into_bytes()) {
                                    Ok(_) => log::info!("Azure upload succeeded for {}", key),
                                    Err(e) => {
                                        log::error!("Azure upload failed for {}: {:?}", key, e);
                                        print_error_chain(&*e);
                                    }
                                }
                            }
                            
                            // Update hash after save
                            *self.ivars().last_saved_hash.lock().unwrap() = compute_content_hash(&s);
                        }
                    }
                }
            }
        }
    }
);

impl WindowDelegate {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(WindowDelegateIvars::default());
        unsafe { msg_send![super(this), init] }
    }
}

// --- Remote File Picker ---
// A custom modal panel that displays S3 bucket keys in a searchable list.

struct RemoteFilePickerIvars {
    all_keys: Mutex<Vec<String>>,
    filtered_keys: Mutex<Vec<String>>,
    selected_key: Mutex<Option<String>>,
    panel: OnceCell<Retained<NSPanel>>,
    table_view: OnceCell<Retained<NSTableView>>,
    search_field: OnceCell<Retained<NSSearchField>>,
    result_confirmed: Mutex<bool>,
}

impl Default for RemoteFilePickerIvars {
    fn default() -> Self {
        Self {
            all_keys: Mutex::new(Vec::new()),
            filtered_keys: Mutex::new(Vec::new()),
            selected_key: Mutex::new(None),
            panel: OnceCell::new(),
            table_view: OnceCell::new(),
            search_field: OnceCell::new(),
            result_confirmed: Mutex::new(false),
        }
    }
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = RemoteFilePickerIvars]
    struct RemoteFilePicker;

    unsafe impl NSObjectProtocol for RemoteFilePicker {}

    unsafe impl NSTableViewDataSource for RemoteFilePicker {
        #[unsafe(method(numberOfRowsInTableView:))]
        fn number_of_rows(&self, _table_view: &NSTableView) -> NSInteger {
            self.ivars().filtered_keys.lock().unwrap().len() as NSInteger
        }

        #[unsafe(method(tableView:objectValueForTableColumn:row:))]
        fn object_value(
            &self,
            _table_view: &NSTableView,
            _column: Option<&NSTableColumn>,
            row: NSInteger,
        ) -> *mut AnyObject {
            let keys = self.ivars().filtered_keys.lock().unwrap();
            if let Some(key) = keys.get(row as usize) {
                let ns_str = NSString::from_str(key);
                Retained::autorelease_return(Retained::into_super(Retained::into_super(ns_str)))
            } else {
                std::ptr::null_mut()
            }
        }
    }

    unsafe impl NSControlTextEditingDelegate for RemoteFilePicker {
        #[unsafe(method(controlTextDidChange:))]
        fn control_text_did_change(&self, _notification: &NSNotification) {
            self.filter_keys();
        }
    }

    unsafe impl NSTableViewDelegate for RemoteFilePicker {
        #[unsafe(method(tableViewSelectionDidChange:))]
        fn selection_did_change(&self, _notification: &NSNotification) {
            if let Some(table) = self.ivars().table_view.get() {
                let row = table.selectedRow();
                let keys = self.ivars().filtered_keys.lock().unwrap();
                if row >= 0 && (row as usize) < keys.len() {
                    *self.ivars().selected_key.lock().unwrap() = Some(keys[row as usize].clone());
                } else {
                    *self.ivars().selected_key.lock().unwrap() = None;
                }
            }
        }
    }

    unsafe impl NSTextFieldDelegate for RemoteFilePicker {}

    unsafe impl NSSearchFieldDelegate for RemoteFilePicker {}

    impl RemoteFilePicker {
        #[unsafe(method(openAction:))]
        fn open_action(&self, _sender: *mut AnyObject) {
            *self.ivars().result_confirmed.lock().unwrap() = true;
            if let Some(panel) = self.ivars().panel.get() {
                let app = NSApplication::sharedApplication(self.mtm());
                app.stopModal();
                panel.orderOut(None);
            }
        }

        #[unsafe(method(cancelAction:))]
        fn cancel_action(&self, _sender: *mut AnyObject) {
            *self.ivars().result_confirmed.lock().unwrap() = false;
            *self.ivars().selected_key.lock().unwrap() = None;
            if let Some(panel) = self.ivars().panel.get() {
                let app = NSApplication::sharedApplication(self.mtm());
                app.stopModal();
                panel.orderOut(None);
            }
        }

        #[unsafe(method(tableDoubleClick:))]
        fn table_double_click(&self, _sender: *mut AnyObject) {
            if self.ivars().selected_key.lock().unwrap().is_some() {
                *self.ivars().result_confirmed.lock().unwrap() = true;
                if let Some(panel) = self.ivars().panel.get() {
                    let app = NSApplication::sharedApplication(self.mtm());
                    app.stopModal();
                    panel.orderOut(None);
                }
            }
        }
    }
);

impl RemoteFilePicker {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(RemoteFilePickerIvars::default());
        unsafe { msg_send![super(this), init] }
    }

    fn filter_keys(&self) {
        let search_text = if let Some(sf) = self.ivars().search_field.get() {
            sf.stringValue().to_string().to_lowercase()
        } else {
            String::new()
        };

        let all = self.ivars().all_keys.lock().unwrap();
        let filtered: Vec<String> = if search_text.is_empty() {
            all.clone()
        } else {
            all.iter()
                .filter(|k| k.to_lowercase().contains(&search_text))
                .cloned()
                .collect()
        };
        
        *self.ivars().filtered_keys.lock().unwrap() = filtered;
        *self.ivars().selected_key.lock().unwrap() = None;

        if let Some(table) = self.ivars().table_view.get() {
            table.reloadData();
        }
    }

    fn run_modal(&self, keys: Vec<String>) -> Option<String> {
        let mtm = self.mtm();
        
        *self.ivars().all_keys.lock().unwrap() = keys.clone();
        *self.ivars().filtered_keys.lock().unwrap() = keys;
        *self.ivars().selected_key.lock().unwrap() = None;
        *self.ivars().result_confirmed.lock().unwrap() = false;

        // Create the panel
        let panel_rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(500.0, 400.0));
        let panel = unsafe {
            let p = NSPanel::initWithContentRect_styleMask_backing_defer(
                NSPanel::alloc(mtm),
                panel_rect,
                NSWindowStyleMask::Titled | NSWindowStyleMask::Closable | NSWindowStyleMask::Resizable,
                NSBackingStoreType::Buffered,
                false,
            );
            p.setReleasedWhenClosed(false);
            p
        };
        panel.setTitle(ns_string!("Open from Cloud"));
        panel.center();

        let content_view = panel.contentView().expect("panel must have content view");

        // Search field at top
        let search_field = NSSearchField::initWithFrame(
            NSSearchField::alloc(mtm),
            NSRect::new(NSPoint::new(20.0, 360.0), NSSize::new(460.0, 24.0)),
        );
        search_field.setPlaceholderString(Some(ns_string!("Search")));
        unsafe { search_field.setDelegate(Some(ProtocolObject::from_ref(self))) };
        content_view.addSubview(&search_field);
        let _ = self.ivars().search_field.set(search_field);

        // Table view for keys
        let scroll_rect = NSRect::new(NSPoint::new(20.0, 50.0), NSSize::new(460.0, 300.0));
        let scroll_view = NSScrollView::initWithFrame(NSScrollView::alloc(mtm), scroll_rect);
        scroll_view.setHasVerticalScroller(true);
        scroll_view.setHasHorizontalScroller(false);
        scroll_view.setBorderType(NSBorderType::BezelBorder);

        let table_rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(460.0, 300.0));
        let table_view = NSTableView::initWithFrame(NSTableView::alloc(mtm), table_rect);
        
        let column = NSTableColumn::initWithIdentifier(
            NSTableColumn::alloc(mtm),
            ns_string!("key"),
        );
        column.setWidth(440.0);
        column.setTitle(ns_string!("Key"));
        table_view.addTableColumn(&column);
        table_view.setHeaderView(None);

        let self_obj: &AnyObject = self.as_ref();
        unsafe {
            table_view.setDataSource(Some(ProtocolObject::from_ref(self)));
            table_view.setDelegate(Some(ProtocolObject::from_ref(self)));
            table_view.setDoubleAction(Some(sel!(tableDoubleClick:)));
            table_view.setTarget(Some(self_obj));
        }

        scroll_view.setDocumentView(Some(&table_view));
        content_view.addSubview(&scroll_view);
        let _ = self.ivars().table_view.set(table_view);

        // Cancel button
        let cancel_button = NSButton::initWithFrame(
            NSButton::alloc(mtm),
            NSRect::new(NSPoint::new(300.0, 10.0), NSSize::new(80.0, 30.0)),
        );
        cancel_button.setTitle(ns_string!("Cancel"));
        #[allow(deprecated)]
        cancel_button.setBezelStyle(NSBezelStyle::Rounded);
        unsafe {
            cancel_button.setAction(Some(sel!(cancelAction:)));
            cancel_button.setTarget(Some(self_obj));
        }
        content_view.addSubview(&cancel_button);

        // Open button
        let open_button = NSButton::initWithFrame(
            NSButton::alloc(mtm),
            NSRect::new(NSPoint::new(390.0, 10.0), NSSize::new(80.0, 30.0)),
        );
        open_button.setTitle(ns_string!("Open"));
        #[allow(deprecated)]
        open_button.setBezelStyle(NSBezelStyle::Rounded);
        unsafe {
            open_button.setAction(Some(sel!(openAction:)));
            open_button.setTarget(Some(self_obj));
        }
        content_view.addSubview(&open_button);

        let _ = self.ivars().panel.set(panel.clone());

        // Run modal
        let app = NSApplication::sharedApplication(mtm);
        app.runModalForWindow(&panel);

        // Return result
        if *self.ivars().result_confirmed.lock().unwrap() {
            self.ivars().selected_key.lock().unwrap().clone()
        } else {
            None
        }
    }
}

// --- Apple Sign In Delegate ---

struct AppleSignInDelegateIvars {
    panel: OnceCell<Retained<NSPanel>>,
    identity_token: Mutex<Option<String>>,
    nonce: Mutex<Option<String>>,
}

impl Default for AppleSignInDelegateIvars {
    fn default() -> Self {
        Self {
            panel: OnceCell::new(),
            identity_token: Mutex::new(None),
            nonce: Mutex::new(None),
        }
    }
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = AppleSignInDelegateIvars]
    struct AppleSignInDelegate;

    unsafe impl NSObjectProtocol for AppleSignInDelegate {}

    unsafe impl ASAuthorizationControllerDelegate for AppleSignInDelegate {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        fn did_complete_with_authorization(
            &self,
            _controller: &ASAuthorizationController,
            authorization: &ASAuthorization,
        ) {
            log::info!("Sign in with Apple succeeded!");

            let credential_obj = unsafe { authorization.credential() };
            if let Ok(apple_id_credential) = Retained::downcast::<ASAuthorizationAppleIDCredential>(credential_obj) {
                if let Some(token_data) = unsafe { apple_id_credential.identityToken() } {
                    let len: usize = unsafe { msg_send![&*token_data, length] };
                    let ptr: *const u8 = unsafe { msg_send![&*token_data, bytes] };
                    let token_bytes = if !ptr.is_null() && len > 0 {
                        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
                    } else {
                        Vec::new()
                    };
                    if let Ok(token_str) = String::from_utf8(token_bytes) {
                        log::info!("Identity token (JWT): {}", token_str);
                        *self.ivars().identity_token.lock().unwrap() = Some(token_str);
                    }
                }

                let user_id = unsafe { apple_id_credential.user() };
                log::info!("User ID: {}", user_id);
            }

            let app = NSApplication::sharedApplication(self.mtm());
            app.stopModal();
            if let Some(panel) = self.ivars().panel.get() {
                panel.orderOut(None);
            }
        }

        #[unsafe(method(authorizationController:didCompleteWithError:))]
        fn did_complete_with_error(
            &self,
            _controller: &ASAuthorizationController,
            error: &NSError,
        ) {
            log::error!("Sign in with Apple failed: {:?}", error);
            let app = NSApplication::sharedApplication(self.mtm());
            app.stopModal();
            if let Some(panel) = self.ivars().panel.get() {
                panel.orderOut(None);
            }
        }
    }

    impl AppleSignInDelegate {
        #[unsafe(method(performSignIn:))]
        fn perform_sign_in(&self, _sender: *mut AnyObject) {
            // First, fetch nonce from server
            let link_code = {
                // Read link code from the text field in the panel
                if let Some(panel) = self.ivars().panel.get() {
                    let content = panel.contentView().expect("panel must have content view");
                    // Find the text field by tag (tag 100)
                    if let Some(view) = content.viewWithTag(100) {
                        let text_field: &objc2_app_kit::NSTextField = unsafe { &*(&*view as *const _ as *const objc2_app_kit::NSTextField) };
                        let text = text_field.stringValue().to_string();
                        if text.len() == 6 && text.chars().all(|c| c.is_ascii_digit()) {
                            Some(text)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            let nonce_url = match &link_code {
                Some(code) => format!("{}/get_nonce?link_code={}", AUTH_BASE_URL, code),
                None => format!("{}/get_nonce", AUTH_BASE_URL),
            };
            log::info!("[Login] Fetching nonce from: {}", nonce_url);

            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("[Login] Failed to create runtime: {}", e);
                    return;
                }
            };

            let nonce = match rt.block_on(async {
                let resp = reqwest::get(&nonce_url).await?;
                resp.text().await
            }) {
                Ok(n) => {
                    log::info!("[Login] Received nonce: {}", n);
                    n
                }
                Err(e) => {
                    log::error!("[Login] Failed to fetch nonce: {}", e);
                    return;
                }
            };

            *self.ivars().nonce.lock().unwrap() = Some(nonce);

            let provider = unsafe { ASAuthorizationAppleIDProvider::new() };
            let request = unsafe { provider.createRequest() };

            // Only request full name — no email scope to avoid the "Share My Email" prompt
            let scopes = unsafe {
                NSArray::from_retained_slice(&[
                    objc2_authentication_services::ASAuthorizationScopeFullName.copy(),
                ])
            };
            unsafe { request.setRequestedScopes(Some(&scopes)) };

            // Set the nonce on the request
            if let Some(nonce) = self.ivars().nonce.lock().unwrap().as_ref() {
                let ns_nonce = NSString::from_str(nonce);
                unsafe { request.setNonce(Some(&ns_nonce)) };
            }

            let request_as_base: Retained<objc2_authentication_services::ASAuthorizationRequest> =
                Retained::into_super(Retained::into_super(request));
            let requests = NSArray::from_retained_slice(&[request_as_base]);

            let controller = unsafe {
                ASAuthorizationController::initWithAuthorizationRequests(
                    ASAuthorizationController::alloc(),
                    &requests,
                )
            };

            unsafe {
                controller.setDelegate(Some(ProtocolObject::from_ref(self)));
                controller.performRequests();
            }
        }
    }
);

impl AppleSignInDelegate {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(AppleSignInDelegateIvars::default());
        unsafe { msg_send![super(this), init] }
    }
}

/// Login result containing the tokens and SAS URL needed for cloud operations
struct LoginResult {
    refresh_token: String,
    container_sas_url: String,
}

/// Performs the full login flow with fallback logic:
/// 1. Show sign-in window (get nonce + Apple Sign In)
/// 2. Send JWT to get_token → get refresh token
/// 3. Send refresh token to get_url → get SAS URL
/// If get_url fails, falls back to get_token. If get_token fails, falls back to sign-in.
fn perform_login(mtm: MainThreadMarker) -> Option<LoginResult> {
    loop {
        // Step 1: Show sign-in window and get identity token
        let identity_token = show_sign_in_window(mtm)?;
        log::info!("[Login] Got identity token ({} chars)", identity_token.len());

        // Step 2: Exchange identity token for refresh token via get_token
        log::info!("[Login] Sending token to get_token endpoint...");
        let refresh_token = match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                match rt.block_on(async {
                    let client = reqwest::Client::new();
                    let url = format!("{}/get_token", AUTH_BASE_URL);
                    log::info!("[Login] POST {}", url);
                    let resp = client
                        .post(&url)
                        .body(identity_token.clone())
                        .send()
                        .await;
                    match resp {
                        Ok(r) => {
                            let status = r.status();
                            log::info!("[Login] get_token response status: {}", status);
                            match r.text().await {
                                Ok(body) => {
                                    log::info!("[Login] get_token response body: {}", body);
                                    if status.is_success() {
                                        Ok(body)
                                    } else {
                                        Err(format!("get_token failed with status {}: {}", status, body))
                                    }
                                }
                                Err(e) => Err(format!("Failed to read get_token response: {}", e)),
                            }
                        }
                        Err(e) => Err(format!("get_token request failed: {}", e)),
                    }
                }) {
                    Ok(token) => {
                        log::info!("[Login] Got refresh token");
                        token
                    }
                    Err(e) => {
                        log::error!("[Login] get_token failed: {}, falling back to sign-in", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                log::error!("[Login] Failed to create tokio runtime: {}, falling back to sign-in", e);
                continue;
            }
        };

        // Step 3: Exchange refresh token for SAS URL via get_url
        log::info!("[Login] Calling get_url...");
        match call_get_url(&refresh_token) {
            Ok((new_refresh_token, url)) => {
                log::info!("[Login] Got SAS URL");
                return Some(LoginResult {
                    refresh_token: new_refresh_token,
                    container_sas_url: url,
                });
            }
            Err(e) => {
                log::error!("[Login] get_url failed: {:?}, falling back to sign-in", e);
                continue; // Fall back to sign-in
            }
        }
    }
}

/// Shows a sign-in window with "Sign in with Apple" button and link code field.
/// Returns the identity token JWT if sign-in succeeded, None if cancelled.
fn show_sign_in_window(mtm: MainThreadMarker) -> Option<String> {
    use objc2_app_kit::{NSView, NSTextField};

    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Regular);
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);

    let panel_rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(400.0, 300.0));
    let panel = unsafe {
        let p = NSPanel::initWithContentRect_styleMask_backing_defer(
            NSPanel::alloc(mtm),
            panel_rect,
            NSWindowStyleMask::Titled | NSWindowStyleMask::Closable,
            NSBackingStoreType::Buffered,
            false,
        );
        p.setReleasedWhenClosed(false);
        p
    };
    panel.setTitle(ns_string!("Sign In"));
    panel.center();

    let content_view = panel.contentView().expect("panel must have content view");

    let sign_in_delegate = AppleSignInDelegate::new(mtm);
    let _ = sign_in_delegate.ivars().panel.set(panel.clone());

    // Sign in with Apple button (centered, upper area)
    let button = unsafe {
        ASAuthorizationAppleIDButton::buttonWithType_style(
            ASAuthorizationAppleIDButtonType::SignIn,
            ASAuthorizationAppleIDButtonStyle::Black,
            mtm,
        )
    };

    let button_width = 250.0;
    let button_height = 44.0;
    let button_x = (400.0 - button_width) / 2.0;
    let button_y = 170.0; // Upper area
    let button_frame = NSRect::new(
        NSPoint::new(button_x, button_y),
        NSSize::new(button_width, button_height),
    );

    let button_as_view: &NSView = unsafe { &*((&*button) as *const _ as *const NSView) };
    button_as_view.setFrame(button_frame);
    content_view.addSubview(button_as_view);

    let delegate_obj: &AnyObject = sign_in_delegate.as_ref();
    let button_as_control: &NSControl = unsafe { &*((&*button) as *const _ as *const NSControl) };
    unsafe {
        button_as_control.setAction(Some(sel!(performSignIn:)));
        button_as_control.setTarget(Some(delegate_obj));
    }

    // Link code label
    let label = NSTextField::initWithFrame(
        NSTextField::alloc(mtm),
        NSRect::new(NSPoint::new(60.0, 110.0), NSSize::new(120.0, 20.0)),
    );
    label.setStringValue(ns_string!("Linking code:"));
    label.setEditable(false);
    label.setBordered(false);
    label.setDrawsBackground(false);
    content_view.addSubview(&label);

    // Link code text field (6-digit number)
    let link_code_field = NSTextField::initWithFrame(
        NSTextField::alloc(mtm),
        NSRect::new(NSPoint::new(180.0, 110.0), NSSize::new(100.0, 24.0)),
    );
    link_code_field.setPlaceholderString(Some(ns_string!("000000")));
    link_code_field.setTag(100); // Tag for retrieval
    content_view.addSubview(&link_code_field);

    // Run modal
    app.runModalForWindow(&panel);

    let result = sign_in_delegate.ivars().identity_token.lock().unwrap().clone();
    result
}

struct AppDelegateIvars {
    is_terminating: Mutex<bool>,
    container_sas_url: Mutex<Option<String>>,
    refresh_token: Mutex<Option<String>>,
}

impl Default for AppDelegateIvars {
    fn default() -> Self {
        Self {
            is_terminating: Mutex::new(false),
            container_sas_url: Mutex::new(None),
            refresh_token: Mutex::new(None),
        }
    }
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = AppDelegateIvars]
    struct AppDelegate;

    unsafe impl NSObjectProtocol for AppDelegate {}

    unsafe impl NSApplicationDelegate for AppDelegate {
        #[unsafe(method(applicationShouldTerminateAfterLastWindowClosed:))]
        fn application_should_terminate_after_last_window_closed(
            &self,
            _sender: &NSApplication,
        ) -> bool {
            true
        }

        #[unsafe(method(applicationWillTerminate:))]
        fn application_will_terminate(&self, _notification: &NSNotification) {
            // Set termination flag so window_will_close skips saving
            *self.ivars().is_terminating.lock().unwrap() = true;

            log::info!("applicationWillTerminate: entering");
            let mtm = self.mtm();
            let app = NSApplication::sharedApplication(mtm);
            log::info!("applicationWillTerminate: window count = {}", app.windows().count());
            save_window_states(mtm);
            log::info!("applicationWillTerminate: exiting");
        }

        #[unsafe(method(applicationDidFinishLaunching:))]
        fn did_finish_launching(&self, notification: &NSNotification) {
            let mtm = self.mtm();

            // Perform login flow: get_nonce → Apple Sign In → get_token → get_url
            if let Some(result) = perform_login(mtm) {
                log::info!("Login succeeded, SAS URL obtained");
                *self.ivars().container_sas_url.lock().unwrap() = Some(result.container_sas_url);
                *self.ivars().refresh_token.lock().unwrap() = Some(result.refresh_token);
            } else {
                log::info!("Login cancelled, continuing in offline mode");
            }

            let app = { notification.object() }
                .unwrap()
                .downcast::<NSApplication>()
                .unwrap();

            // Try to restore window states from previous session
            let saved_states = load_window_states(mtm);
            
            if !saved_states.is_empty() {
                // Restore all windows from saved state
                for state in saved_states {
                    create_window_from_state(state, mtm);
                }
                
                // Setup app and menus
                app.setActivationPolicy(NSApplicationActivationPolicy::Regular);
                #[allow(deprecated)]
                app.activateIgnoringOtherApps(true);
                
                // Create menu (code below will handle this)
            } else {
                // No saved state - create default window with notes.txt
                create_window(mtm, "notes.txt", None);
                
                app.setActivationPolicy(NSApplicationActivationPolicy::Regular);

                // Activate the application.
                // Required when launching unbundled (as is done with Cargo).
                #[allow(deprecated)]
                app.activateIgnoringOtherApps(true);
            }
            
            // Create application menu
            let main_menu = NSMenu::new(mtm);
            
            let file_menu_item = NSMenuItem::new(mtm);
            file_menu_item.setTitle(ns_string!("File"));
            
            let file_submenu = NSMenu::initWithTitle(NSMenu::alloc(mtm), ns_string!("File"));
            
            // Open (Cmd+O) - target is app delegate
            let new_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Open…"),
                    Some(sel!(newWindow:)),
                    ns_string!("o"))
            };
            let delegate_obj = app.delegate();
            if let Some(ref d) = delegate_obj {
                let target: &AnyObject = (&**d).as_ref();
                unsafe { new_item.setTarget(Some(target)) };
            }
            new_item.setEnabled(true);
            new_item.setKeyEquivalentModifierMask(NSEventModifierFlags::Command);
            
            // New Window (Cmd+N) - opens local file picker
            let new_local_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("New Window"),
                    Some(sel!(newWindowLocal:)),
                    ns_string!("n"))
            };
            if let Some(ref d) = delegate_obj {
                let target: &AnyObject = (&**d).as_ref();
                unsafe { new_local_item.setTarget(Some(target)) };
            }
            new_local_item.setEnabled(true);
            new_local_item.setKeyEquivalentModifierMask(NSEventModifierFlags::Command);
            
            // Save As (Cmd+Shift+S) - target is nil (uses responder chain to find window delegate)
            let save_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Save As…"),
                    Some(sel!(saveAs:)),
                    ns_string!("S"))
            };
            save_item.setKeyEquivalentModifierMask(
                NSEventModifierFlags::Command | NSEventModifierFlags::Shift);
            
            file_submenu.addItem(&new_local_item);
            file_submenu.addItem(&new_item);
            file_submenu.addItem(&save_item);
            file_menu_item.setSubmenu(Some(&file_submenu));
            main_menu.addItem(&file_menu_item);
            
            // Create Edit menu for copy/paste support
            let edit_menu_item = NSMenuItem::new(mtm);
            edit_menu_item.setTitle(ns_string!("Edit"));
            
            let edit_submenu = NSMenu::initWithTitle(NSMenu::alloc(mtm), ns_string!("Edit"));
            
            let undo_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Undo"),
                    Some(sel!(undo:)),
                    ns_string!("z"))
            };
            
            let redo_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Redo"),
                    Some(sel!(redo:)),
                    ns_string!("Z"))
            };
            redo_item.setKeyEquivalentModifierMask(
                NSEventModifierFlags::Command | NSEventModifierFlags::Shift);
            
            let cut_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Cut"),
                    Some(sel!(cut:)),
                    ns_string!("x"))
            };
            
            let copy_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Copy"),
                    Some(sel!(copy:)),
                    ns_string!("c"))
            };
            
            let paste_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Paste"),
                    Some(sel!(paste:)),
                    ns_string!("v"))
            };
            
            let select_all_item = unsafe {
                NSMenuItem::initWithTitle_action_keyEquivalent(
                    NSMenuItem::alloc(mtm),
                    ns_string!("Select All"),
                    Some(sel!(selectAll:)),
                    ns_string!("a"))
            };
            
            edit_submenu.addItem(&undo_item);
            edit_submenu.addItem(&redo_item);
            edit_submenu.addItem(&NSMenuItem::separatorItem(mtm));
            edit_submenu.addItem(&cut_item);
            edit_submenu.addItem(&copy_item);
            edit_submenu.addItem(&paste_item);
            edit_submenu.addItem(&NSMenuItem::separatorItem(mtm));
            edit_submenu.addItem(&select_all_item);
            edit_menu_item.setSubmenu(Some(&edit_submenu));
            main_menu.addItem(&edit_menu_item);
            
            app.setMainMenu(Some(&main_menu));
            
            // Schedule auto-save timer (fires every 5 minutes)
            let delegate_obj = app.delegate();
            if let Some(ref d) = delegate_obj {
                let target: &AnyObject = (&**d).as_ref();
                let _timer = unsafe {
                    NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                        300.0, // 5 minutes
                        target,
                        sel!(autoSave:),
                        None,
                        true,
                    )
                };
                log::info!("Auto-save timer scheduled (every 5 minutes)");
            }
        }
    }

    impl AppDelegate {
        #[unsafe(method(autoSave:))]
        fn auto_save(&self, _timer: *mut objc2::runtime::AnyObject) {
            log::debug!(" auto_save: timer fired!");
            auto_save_all_windows(self.mtm());
        }
    }

    impl AppDelegate {
        #[unsafe(method(newWindow:))]
        fn new_window(&self, _sender: *mut objc2::runtime::AnyObject) {
            let mtm = self.mtm();
            log::info!("new_window selector invoked");
            
            // Get container SAS URL
            let sas_url = match self.ivars().container_sas_url.lock().unwrap().clone() {
                Some(url) => url,
                None => {
                    log::error!("No Azure SAS URL configured - cannot open remote file picker");
                    return;
                }
            };
            
            // List all blobs from the container
            log::info!("Listing blobs from Azure container...");
            let keys = match azure_list_keys(&sas_url) {
                Ok(k) => {
                    log::info!("Found {} blobs", k.len());
                    k
                }
                Err(e) => {
                    log::error!("Failed to list Azure blobs: {:?}", e);
                    // Fallback: try to refresh SAS URL
                    if let Some(ref token) = *self.ivars().refresh_token.lock().unwrap() {
                        match call_get_url(token) {
                            Ok((new_token, new_url)) => {
                                *self.ivars().refresh_token.lock().unwrap() = Some(new_token);
                                *self.ivars().container_sas_url.lock().unwrap() = Some(new_url.clone());
                                match azure_list_keys(&new_url) {
                                    Ok(k) => k,
                                    Err(e2) => {
                                        log::error!("Failed to list after URL refresh: {:?}", e2);
                                        return;
                                    }
                                }
                            }
                            Err(e2) => {
                                log::error!("Failed to refresh SAS URL: {:?}", e2);
                                return;
                            }
                        }
                    } else {
                        return;
                    }
                }
            };
            
            if keys.is_empty() {
                log::error!("No files found in Azure container");
                return;
            }
            
            // Show custom file picker
            let picker = RemoteFilePicker::new(mtm);
            let Some(selected_key) = picker.run_modal(keys) else {
                log::info!("File picker cancelled");
                return;
            };
            
            log::info!("Selected key: {}", selected_key);
            
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let local_path = PathBuf::from(&home).join("Notes").join(&selected_key);
            
            if let Some(parent) = local_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            
            // Get latest SAS URL (may have been refreshed)
            let current_sas = self.ivars().container_sas_url.lock().unwrap().clone()
                .unwrap_or(sas_url);
            
            // Download from Azure
            match azure_download(&current_sas, &selected_key) {
                Ok(bytes) => {
                    if let Err(e) = std::fs::write(&local_path, &bytes) {
                        log::error!("Failed to write file to {}: {}", local_path.display(), e);
                        return;
                    }
                    log::info!("Downloaded {} to {}", selected_key, local_path.display());
                }
                Err(e) => {
                    log::error!("Failed to download {}: {:?}", selected_key, e);
                    return;
                }
            }
            
            create_window(mtm, &local_path.to_string_lossy(), None);
        }

        #[unsafe(method(newWindowLocal:))]
        fn new_window_local(&self, _sender: *mut objc2::runtime::AnyObject) {
            let mtm = self.mtm();
            log::info!("newWindowLocal selector invoked");
            
            // Generate a unique dated filename in ~/Notes/
            let file_path = generate_unique_dated_filepath();
            
            // Create an empty file
            if let Err(e) = std::fs::write(&file_path, "") {
                log::error!("Failed to create file {}: {}", file_path.display(), e);
                return;
            }
            
            // Create window using unified function
            create_window(mtm, &file_path.to_string_lossy(), None);
        }
    }
);

impl AppDelegate {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(AppDelegateIvars::default());
        unsafe { msg_send![super(this), init] }
    }
}

/// Check if the application is in the process of terminating
fn is_app_terminating(mtm: MainThreadMarker) -> bool {
    let app = NSApplication::sharedApplication(mtm);
    let Some(delegate_proto) = app.delegate() else {
        return false;
    };
    let delegate_obj: Retained<NSObject> = unsafe { 
        Retained::cast_unchecked(delegate_proto) 
    };
    let Ok(delegate) = Retained::downcast::<AppDelegate>(delegate_obj) else {
        return false;
    };
    let result = *delegate.ivars().is_terminating.lock().unwrap();
    result
}

/// Get the container SAS URL from the AppDelegate, if configured
fn get_container_sas_url(mtm: MainThreadMarker) -> Option<String> {
    let app = NSApplication::sharedApplication(mtm);
    let delegate_proto = app.delegate()?;
    let delegate_obj: Retained<NSObject> = unsafe { 
        Retained::cast_unchecked(delegate_proto) 
    };
    let delegate = Retained::downcast::<AppDelegate>(delegate_obj).ok()?;
    let result = delegate.ivars().container_sas_url.lock().unwrap().clone();
    result
}

/// Get a reference to the AppDelegate
fn get_app_delegate(mtm: MainThreadMarker) -> Option<Retained<AppDelegate>> {
    let app = NSApplication::sharedApplication(mtm);
    let delegate_proto = app.delegate()?;
    let delegate_obj: Retained<NSObject> = unsafe { 
        Retained::cast_unchecked(delegate_proto) 
    };
    Retained::downcast::<AppDelegate>(delegate_obj).ok()
}

fn main() {
    // Initialize unified macOS logging (os_log)
    oslog::OsLogger::new("com.weatjar.notes")
        .level_filter(log::LevelFilter::Debug)
        .init()
        .expect("failed to init os_log logger");

    let mtm = MainThreadMarker::new().unwrap();

    let app = NSApplication::sharedApplication(mtm);
    let delegate = AppDelegate::new(mtm);
    app.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));

    app.run();
}