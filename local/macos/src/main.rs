#![deny(unsafe_op_in_unsafe_fn)]
use std::cell::OnceCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
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
};
use objc2_foundation::{
    ns_string, MainThreadMarker, NSNotification, NSObject, NSObjectProtocol, NSPoint, NSRect,
    NSSize, NSString, NSUserDefaults, NSDictionary, NSNumber, NSMutableArray, NSArray, NSURL,
    NSInteger, NSTimer,
};

// AWS + HTTP
use aws_config;
use aws_sdk_s3::Client as S3Client;
// Using `aws_config::load_from_env()` to get credentials from environment/profile.
use aws_sdk_s3::primitives::ByteStream;
use chrono::Utc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    println!("NSApplication windows count: {}", windows.count());
    
    // Debug: print info about each window
    for (i, window) in windows.iter().enumerate() {
        let title_rust = window.title().to_string();
        let is_visible = window.isVisible();
        let has_delegate = window.delegate().is_some();
        println!("  Window {}: title='{}', visible={}, has_delegate={}", 
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
        println!("No window states to save, preserving existing states");
        return;
    }
    
    let defaults = NSUserDefaults::standardUserDefaults();
    // Safety: array is a valid NSMutableArray containing NSDictionary objects
    unsafe {
        defaults.setObject_forKey(Some(&array), ns_string!("windowStates"));
    }
    
    println!("Saved {} window states", count);
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
    
    println!("Loaded {} window states (cleared from storage)", states.len());
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
    
    let bucket = std::env::var("S3_BUCKET").ok();
    let app_delegate = get_s3_client(mtm);
    let s3_client = app_delegate.as_ref().and_then(|d| d.ivars().s3_client.get());
    let file_content = load_file_content(&file_path, bucket.as_deref(), s3_client);
    
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
    eprintln!("error: {}", err);
    let mut src = err.source();
    while let Some(s) = src {
        eprintln!("caused by: {}", s);
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
    
    println!("[DEBUG] auto_save_all_windows: checking {} windows", windows.count());
    
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
            println!("[DEBUG] auto_save: no changes in {} (hash match)", file_path.display());
            continue;
        }
        
        println!("Auto-save: changes detected in {}", file_path.display());
        
        // Save locally
        match std::fs::write(&file_path, &content) {
            Ok(_) => println!("Auto-save: wrote to {}", file_path.display()),
            Err(e) => {
                eprintln!("Auto-save: failed to write {}: {}", file_path.display(), e);
                continue;
            }
        }
        
        // Upload to S3 if configured
        if let Ok(bucket) = std::env::var("S3_BUCKET") {
            let key = file_path.file_name()
                .and_then(|os| os.to_str())
                .unwrap_or("notes.txt")
                .to_string();
            
            if let Some(app_delegate) = get_s3_client(mtm) {
                if let Some(client) = app_delegate.ivars().s3_client.get() {
                    match s3_upload(client, &bucket, &key, content.clone().into_bytes()) {
                        Ok(_) => println!("Auto-save: S3 upload succeeded for s3://{}/{}", bucket, key),
                        Err(e) => {
                            eprintln!("Auto-save: S3 upload failed: {:?}", e);
                            print_error_chain(&*e);
                        }
                    }
                }
            }
        }
        
        // Update hash
        *delegate.ivars().last_saved_hash.lock().unwrap() = current_hash;
    }
}

// --- S3 Helper Functions ---
// These functions accept a pre-initialized S3 client for reuse across operations.

/// Upload content to S3.
fn s3_upload(client: &S3Client, bucket: &str, key: &str, body: Vec<u8>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rt = tokio::runtime::Runtime::new()?;
    let bucket = bucket.to_string();
    let key = key.to_string();
    rt.block_on(async {
        client
            .put_object()
            .bucket(&bucket)
            .key(&key)
            .content_type("text/plain")
            .body(ByteStream::from(body))
            .send()
            .await
            .map(|_| ())
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))
    })
}

/// Download content from S3. Returns the raw bytes.
fn s3_download(client: &S3Client, bucket: &str, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let rt = tokio::runtime::Runtime::new()?;
    let bucket = bucket.to_string();
    let key = key.to_string();
    rt.block_on(async {
        let resp = client
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;
        let bytes = resp.body.collect().await
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;
        Ok(bytes.into_bytes().to_vec())
    })
}

/// Get the last modified time of an S3 object.
fn s3_last_modified(client: &S3Client, bucket: &str, key: &str) -> Result<Option<SystemTime>, Box<dyn std::error::Error + Send + Sync>> {
    let rt = tokio::runtime::Runtime::new()?;
    let bucket = bucket.to_string();
    let key = key.to_string();
    let maybe_dt = rt.block_on(async {
        match client.head_object().bucket(&bucket).key(&key).send().await {
            Ok(head_out) => Ok(head_out.last_modified().cloned()),
            Err(e) => Err(Box::<dyn std::error::Error + Send + Sync>::from(e)),
        }
    })?;

    let mtime: Option<SystemTime> = maybe_dt.and_then(|dt| {
        let s = dt.to_string();
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&s) {
            let utc = parsed.with_timezone(&Utc);
            let secs = utc.timestamp();
            let nsecs = utc.timestamp_subsec_nanos();
            return UNIX_EPOCH.checked_add(Duration::new(secs as u64, nsecs));
        }
        None
    });

    Ok(mtime)
}

/// List all object keys from an S3 bucket. Uses pagination to handle large buckets.
fn s3_list_keys(client: &S3Client, bucket: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let rt = tokio::runtime::Runtime::new()?;
    let bucket = bucket.to_string();
    
    rt.block_on(async {
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;
        
        loop {
            let mut req = client.list_objects_v2().bucket(&bucket);
            if let Some(token) = continuation_token.take() {
                req = req.continuation_token(token);
            }
            
            let resp = req.send().await?;
            
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    keys.push(key.to_string());
                }
            }
            
            if resp.is_truncated() == Some(true) {
                continuation_token = resp.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }
        
        keys.sort();
        Ok(keys)
    })
}

// Load file content from either S3 or local filesystem, preferring whichever is newer.
// Returns `Some(content)` if a file was found, `None` if neither local nor S3 has the file.
// If S3 is configured and has a newer version, it will be downloaded to the local path.
fn load_file_content(path: &PathBuf, bucket: Option<&str>, s3_client: Option<&S3Client>) -> Option<String> {
    let mut file_content: Option<String> = None;

    // Get local modified time if the file exists
    let local_mtime: Option<SystemTime> = match std::fs::metadata(path) {
        Ok(md) => md.modified().ok(),
        Err(_) => None,
    };

    // If S3 is configured and client is available, try to compare timestamps and conditionally use S3 data.
    if let (Some(bucket), Some(client)) = (bucket, s3_client) {
        // Derive the S3 key from the filename
        let key = path
            .file_name()
            .and_then(|os| os.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| String::from("notes.txt"));

        // Determine whether the S3 object is newer than the local file
        match s3_last_modified(client, bucket, &key) {
            Ok(bucket_mtime) => {
                let should_use_bucket = match (bucket_mtime, local_mtime) {
                    (Some(bm), Some(lm)) => bm > lm,
                    (Some(_bm), None) => true,
                    _ => false,
                };

                if should_use_bucket {
                    match s3_download(client, bucket, &key) {
                        Ok(bytes) => {
                            if let Err(e) = std::fs::write(path, &bytes) {
                                eprintln!("Failed to write S3 notes to {}: {}", path.display(), e);
                            } else if let Ok(s) = String::from_utf8(bytes) {
                                file_content = Some(s);
                                println!("Loaded from S3: s3://{}/{} -> {}", bucket, key, path.display());
                            }
                        }
                        Err(e) => {
                            // S3 object doesn't exist or other error - this is OK, we'll fall back to local
                            eprintln!("S3 object not found or error s3://{}/{}: {:?}", bucket, key, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("S3 HEAD error: {:?}; will fall back to local file", e);
            }
        }
    }

    // If we haven't set file_content from S3, try to read local file now.
    if file_content.is_none() {
        if let Ok(s) = std::fs::read_to_string(path) {
            file_content = Some(s);
            println!("Loaded from local file: {}", path.display());
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
                Ok(_) => println!("Wrote notes to {}", file_path.display()),
                Err(e) => eprintln!("Failed to write notes to {}: {}", file_path.display(), e),
            }

            // Upload to S3 if configured
            if let Ok(bucket) = std::env::var("S3_BUCKET") {
                let key = file_path.file_name()
                    .and_then(|os| os.to_str())
                    .unwrap_or("notes.txt")
                    .to_string();
                println!("S3 upload: s3://{}/{} ({} bytes)", bucket, key, content.len());
                
                if let Some(app_delegate) = get_s3_client(self.mtm()) {
                    if let Some(client) = app_delegate.ivars().s3_client.get() {
                        match s3_upload(client, &bucket, &key, content.clone().into_bytes()) {
                            Ok(_) => println!("S3 upload succeeded for s3://{}/{}", bucket, key),
                            Err(e) => {
                                eprintln!("S3 upload failed: {:?}", e);
                                print_error_chain(&*e);
                            }
                        }
                    }
                } else {
                    eprintln!("S3 client not initialized");
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
            
            println!("Saved window state (replacing previous)");

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
                                eprintln!("Failed to write file {}: {}", chosen, e);
                            } else {
                                println!("Wrote notes to {}", chosen);
                            }

                            if let Ok(bucket) = std::env::var("S3_BUCKET") {
                                // Derive S3 key from file basename
                                let key = std::path::Path::new(&chosen)
                                    .file_name()
                                    .and_then(|os| os.to_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| String::from("notes.txt"));

                                println!("S3 upload requested: bucket='{}' key='{}' size={} bytes", bucket, key, s.len());
                                
                                if let Some(app_delegate) = get_s3_client(self.mtm()) {
                                    if let Some(client) = app_delegate.ivars().s3_client.get() {
                                        match s3_upload(client, &bucket, &key, s.clone().into_bytes()) {
                                            Ok(_) => println!("S3 upload succeeded for s3://{}/{}", bucket, key),
                                            Err(e) => {
                                                eprintln!("S3 upload failed for s3://{}/{}: {:?}", bucket, key, e);
                                                print_error_chain(&*e);
                                            }
                                        }
                                    }
                                } else {
                                    eprintln!("S3 client not initialized");
                                }
                            } else {
                                println!("S3_BUCKET not set; skipping upload to S3");
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

/// Shows a sign-in window with "Sign in with Apple" button.
/// Returns true if user clicked sign in, false if cancelled/closed.
fn show_sign_in_window(mtm: MainThreadMarker) -> bool {
    use objc2_app_kit::NSView;
    
    // Activate app first so modal window can be shown
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Regular);
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);
    
    // Create the panel
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
    
    // Create Sign in with Apple button (centered)
    let button = unsafe {
        ASAuthorizationAppleIDButton::buttonWithType_style(
            ASAuthorizationAppleIDButtonType::SignIn,
            ASAuthorizationAppleIDButtonStyle::Black,
            mtm,
        )
    };
    
    // Set button frame (centered in window, Apple recommends min 140x30)
    let button_width = 250.0;
    let button_height = 44.0;
    let button_x = (400.0 - button_width) / 2.0;
    let button_y = (300.0 - button_height) / 2.0;
    let button_frame = NSRect::new(
        NSPoint::new(button_x, button_y),
        NSSize::new(button_width, button_height),
    );
    
    // Cast button to NSView and set frame
    let button_as_view: &NSView = unsafe { &*((&*button) as *const _ as *const NSView) };
    button_as_view.setFrame(button_frame);
    content_view.addSubview(button_as_view);
    
    // Set action to stopModal via NSControl
    let button_as_control: &NSControl = unsafe { &*((&*button) as *const _ as *const NSControl) };
    unsafe {
        button_as_control.setAction(Some(sel!(stopModal)));
        button_as_control.setTarget(Some(&*app));
    }
    
    // Run modal
    let response = app.runModalForWindow(&panel);
    
    // NSModalResponseStop (0) means stopModal was called (button clicked)
    panel.orderOut(None);
    
    // If the response indicates the modal was stopped (not aborted), user clicked sign in
    response == objc2_app_kit::NSModalResponseStop
}

struct AppDelegateIvars {
    is_terminating: Mutex<bool>,
    s3_client: OnceCell<S3Client>,
}

impl Default for AppDelegateIvars {
    fn default() -> Self {
        Self {
            is_terminating: Mutex::new(false),
            s3_client: OnceCell::new(),
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

            println!("applicationWillTerminate: entering");
            let mtm = self.mtm();
            let app = NSApplication::sharedApplication(mtm);
            println!("applicationWillTerminate: window count = {}", app.windows().count());
            save_window_states(mtm);
            println!("applicationWillTerminate: exiting");
        }

        #[unsafe(method(applicationDidFinishLaunching:))]
        fn did_finish_launching(&self, notification: &NSNotification) {
            let mtm = self.mtm();

            // Check if AWS credentials are configured
            if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
                // Show sign-in window first
                let signed_in = show_sign_in_window(mtm);
                println!("Sign in result: {}", signed_in);
                // For now, continue regardless of result (placeholder)
            }

            // Initialize S3 client if S3_BUCKET is configured
            if std::env::var("S3_BUCKET").is_ok() {
                match tokio::runtime::Runtime::new() {
                    Ok(rt) => {
                        let client = rt.block_on(async {
                            let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                            S3Client::new(&cfg)
                        });
                        let _ = self.ivars().s3_client.set(client);
                        println!("S3 client initialized");
                    }
                    Err(e) => {
                        eprintln!("Failed to create tokio runtime for S3 client init: {}", e);
                    }
                }
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
                println!("Auto-save timer scheduled (every 5 minutes)");
            }
        }
    }

    impl AppDelegate {
        #[unsafe(method(autoSave:))]
        fn auto_save(&self, _timer: *mut objc2::runtime::AnyObject) {
            println!("[DEBUG] auto_save: timer fired!");
            auto_save_all_windows(self.mtm());
        }
    }

    impl AppDelegate {
        #[unsafe(method(newWindow:))]
        fn new_window(&self, _sender: *mut objc2::runtime::AnyObject) {
            let mtm = self.mtm();
            println!("new_window selector invoked");
            
            // Check if S3 is configured
            let bucket = match std::env::var("S3_BUCKET") {
                Ok(b) => b,
                Err(_) => {
                    eprintln!("S3_BUCKET not configured - cannot open remote file picker");
                    return;
                }
            };
            
            // Get S3 client
            let Some(client) = self.ivars().s3_client.get() else {
                eprintln!("S3 client not initialized");
                return;
            };
            
            // List all keys from the bucket
            println!("Listing keys from S3 bucket: {}", bucket);
            let keys = match s3_list_keys(client, &bucket) {
                Ok(k) => {
                    println!("Found {} keys in bucket", k.len());
                    k
                }
                Err(e) => {
                    eprintln!("Failed to list S3 bucket keys: {:?}", e);
                    return;
                }
            };
            
            if keys.is_empty() {
                eprintln!("No files found in bucket");
                return;
            }
            
            // Show custom file picker
            let picker = RemoteFilePicker::new(mtm);
            let Some(selected_key) = picker.run_modal(keys) else {
                println!("File picker cancelled");
                return;
            };
            
            println!("Selected key: {}", selected_key);
            
            // Download the file from S3 and create local copy
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let local_path = PathBuf::from(&home).join("Notes").join(&selected_key);
            
            // Create parent directories if needed
            if let Some(parent) = local_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            
            // Download from S3
            match s3_download(client, &bucket, &selected_key) {
                Ok(bytes) => {
                    if let Err(e) = std::fs::write(&local_path, &bytes) {
                        eprintln!("Failed to write file to {}: {}", local_path.display(), e);
                        return;
                    }
                    println!("Downloaded s3://{}/{} to {}", bucket, selected_key, local_path.display());
                }
                Err(e) => {
                    eprintln!("Failed to download s3://{}/{}: {:?}", bucket, selected_key, e);
                    return;
                }
            }
            
            // Create window with the downloaded file
            create_window(mtm, &local_path.to_string_lossy(), None);
        }

        #[unsafe(method(newWindowLocal:))]
        fn new_window_local(&self, _sender: *mut objc2::runtime::AnyObject) {
            let mtm = self.mtm();
            println!("newWindowLocal selector invoked");
            
            // Generate a unique dated filename in ~/Notes/
            let file_path = generate_unique_dated_filepath();
            
            // Create an empty file
            if let Err(e) = std::fs::write(&file_path, "") {
                eprintln!("Failed to create file {}: {}", file_path.display(), e);
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

/// Get a reference to the S3 client from the AppDelegate, if configured
fn get_s3_client(mtm: MainThreadMarker) -> Option<Retained<AppDelegate>> {
    let app = NSApplication::sharedApplication(mtm);
    let delegate_proto = app.delegate()?;
    let delegate_obj: Retained<NSObject> = unsafe { 
        Retained::cast_unchecked(delegate_proto) 
    };
    let delegate = Retained::downcast::<AppDelegate>(delegate_obj).ok()?;
    // Only return if client is initialized
    if delegate.ivars().s3_client.get().is_some() {
        Some(delegate)
    } else {
        None
    }
}

fn main() {
    let mtm = MainThreadMarker::new().unwrap();

    let app = NSApplication::sharedApplication(mtm);
    let delegate = AppDelegate::new(mtm);
    app.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));

    app.run();
}