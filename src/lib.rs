use pmod::fmg::MsgRepository;
use std::ptr::NonNull;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

fn init() {
    for category in MsgRepository::get_all_categories(0).unwrap_or_default() {
        for (id, msg_ptr) in MsgRepository::get_all_msgs(0, category).unwrap_or_default() {
            let msg = unsafe {
                let mut len = 0;
                while *msg_ptr.as_ptr().add(len) != 0 {
                    len += 1;
                }
                std::slice::from_raw_parts(msg_ptr.as_ptr(), len)
            };
            let mut utf8_string = String::from_utf16_lossy(msg);

            // Collect tags using SSE-based search
            let tags = find_tags_sse(&utf8_string);

            // Replace tags with underscores in-place (manual replacement)
            let mut result = String::with_capacity(utf8_string.len());
            let mut last_end = 0;
            for tag in &tags {
                if let Some(start) = utf8_string[last_end..].find(tag) {
                    let abs_start = last_end + start;
                    result.push_str(&utf8_string[last_end..abs_start]);
                    result.push_str(&"_".repeat(tag.len()));
                    last_end = abs_start + tag.len();
                }
            }
            result.push_str(&utf8_string[last_end..]);
            utf8_string = result;

            let mut uwuified = uwuifier::uwuify_str_sse(&utf8_string)
                .replace(">w<", "^w^")
                .replace(">_<", "w_w");

            // Re-insert tags by replacing underscore sequences
            for tag in tags {
                let replace_target = "_".repeat(tag.len());
                uwuified = uwuified.replacen(&replace_target, &tag, 1);
            }

            let uwuified_utf16: Vec<u16> =
                uwuified.encode_utf16().chain(std::iter::once(0)).collect();

            let layout = std::alloc::Layout::from_size_align(
                uwuified_utf16.len() * std::mem::size_of::<u16>(),
                std::mem::align_of::<u16>(),
            )
            .unwrap();
            let new_data_ptr = unsafe { std::alloc::alloc(layout) } as *mut u16;
            if new_data_ptr.is_null() {
                continue;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    uwuified_utf16.as_ptr(),
                    new_data_ptr,
                    uwuified_utf16.len(),
                );
            }

            MsgRepository::replace_msg(0, category, id, NonNull::new(new_data_ptr)).unwrap();
        }
    }
}

/// Finds all tags like "<?...>" using SSE4.1 for fast substring search.
/// Returns a Vec of tag strings.
#[cfg(target_arch = "x86_64")]
fn find_tags_sse(s: &str) -> Vec<String> {
    if !is_x86_feature_detected!("sse4.1") {
        // Fallback to simple search if SSE4.1 not available
        return find_tags_fallback(s);
    }
    let bytes = s.as_bytes();
    let mut tags = Vec::new();
    let mut i = 0;
    let start_pattern = b"<?";
    let end_char = b'>';
    while i < bytes.len() {
        // Load chunk and search for "<?"
        let chunk = unsafe { _mm_loadu_si128(bytes.as_ptr().add(i).cast()) };
        let start_mask = unsafe {
            _mm_cmpestri(
                chunk,
                2,
                _mm_loadu_si128(start_pattern.as_ptr().cast()),
                2,
                _SIDD_CMP_EQUAL_ORDERED,
            )
        };
        if start_mask < 16 {
            let tag_start = i + start_mask as usize;
            // Find closing ">"
            let mut tag_end = tag_start + 2;
            while tag_end < bytes.len() && bytes[tag_end] != end_char {
                tag_end += 1;
            }
            if tag_end < bytes.len() {
                tag_end += 1; // Include '>'
                if let Ok(tag) = std::str::from_utf8(&bytes[tag_start..tag_end]) {
                    tags.push(tag.to_string());
                }
                i = tag_end;
            } else {
                break;
            }
        } else {
            i += 16 - 2; // Advance by chunk size minus overlap
        }
    }
    tags
}

#[cfg(not(target_arch = "x86_64"))]
fn find_tags_sse(s: &str) -> Vec<String> {
    find_tags_fallback(s)
}

fn find_tags_fallback(s: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut i = 0;
    while let Some(start) = s[i..].find("<?") {
        let abs_start = i + start;
        if let Some(end_offset) = s[abs_start + 2..].find('>') {
            let tag_end = abs_start + 2 + end_offset + 1;
            tags.push(s[abs_start..tag_end].to_string());
            i = tag_end;
        } else {
            break;
        }
    }
    tags
}

fn wait_for_message_repository() {
    loop {
        // try to get (dummyText) from Talk Messages
        // if MsgRepository is not initialized yet, this will return None
        if MsgRepository::get_msg(0, 1, 100).is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        std::thread::yield_now();
    }
}

unsafe extern "system" {
    unsafe fn DisableThreadLibraryCalls(hinst: usize);
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
/// # Safety
///
/// Safe if called by LoadLibrary
pub unsafe extern "system" fn DllMain(hinst: usize, reason: u32, _reserved: usize) -> bool {
    // DLL_PROCESS_ATTACH
    if reason == 1 {
        unsafe { DisableThreadLibraryCalls(hinst) };
        std::thread::spawn(|| {
            wait_for_message_repository();
            init();
        });
    };
    true
}
