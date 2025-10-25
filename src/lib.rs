use pmod::fmg::MsgRepository;
use std::ptr::NonNull;

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
            let utf8_string = String::from_utf16_lossy(msg);
            let tags = find_tags(&utf8_string);
            let escaped_string = escape_tags(&utf8_string, &tags);
            let mut uwuified = uwuifier::uwuify_str_sse(&escaped_string)
                .replace(">w<", "^w^")
                .replace(">_<", "w_w");
            uwuified = reinsert_tags(&uwuified, &tags);

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

fn find_tags(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut tags = Vec::new();
    let mut i = 0;
    let len = bytes.len();

    while i + 1 < len {
        // Look for '<?'
        if bytes[i] == b'<' && bytes[i + 1] == b'?' {
            let start = i;
            // Scan for '>' after '<?'
            let mut j = i + 2;
            while j < len && bytes[j] != b'>' {
                j += 1;
            }
            if j < len {
                if let Ok(tag) = std::str::from_utf8(&bytes[start..=j]) {
                    tags.push(tag.to_string());
                }
                i = j + 1;
                continue;
            } else {
                break;
            }
        }
        i += 1;
    }
    tags
}

fn reinsert_tags(s: &str, tags: &Vec<String>) -> String {
    let mut result = s.to_string();
    for tag in tags {
        let replace_target = "_".repeat(tag.len());
        result = result.replacen(&replace_target, tag, 1);
    }
    result
}

fn escape_tags(s: &str, tags: &Vec<String>) -> String {
    let mut result = s.to_string();
    for tag in tags {
        result = result.replacen(tag, &"_".repeat(tag.len()), 1);
    }
    result
}

fn wait_for_message_repository() {
    loop {
        // try to get `x` from Menu Text category
        // if MsgRepository is not initialized yet, this will return None
        if MsgRepository::get_msg(0, 200, 1010).is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_tags() {
        let test_str = "Hello <?tag1?> world <?tag2?>!";
        let tags = find_tags(test_str);
        assert_eq!(tags, vec!["<?tag1?>", "<?tag2?>"]);
    }

    #[test]
    fn test_reinsert_tags() {
        let test_str = "Hello ________ world ________!";
        let tags = vec!["<?tag1?>".to_string(), "<?tag2?>".to_string()];
        let result = reinsert_tags(test_str, &tags);
        assert_eq!(result, "Hello <?tag1?> world <?tag2?>!");
    }

    #[test]
    fn test_escape_tags() {
        let test_str = "Hello <?tag1?> world <?tag2?>!";
        let tags = vec!["<?tag1?>".to_string(), "<?tag2?>".to_string()];
        let result = escape_tags(test_str, &tags);
        assert_eq!(result, "Hello ________ world ________!");
    }

    #[test]
    fn test_uwuify_integration() {
        let test_str = "Hello <?hello?> world <?world?>!";
        let tags = find_tags(test_str);
        let escaped = escape_tags(test_str, &tags);
        let mut uwuified = uwuifier::uwuify_str_sse(&escaped)
            .replace(">w<", "^w^")
            .replace(">_<", "w_w");
        uwuified = reinsert_tags(&uwuified, &tags);
        assert_eq!(uwuified, "Hewwo <?hello?> wowwd <?world?>!");
    }
}
