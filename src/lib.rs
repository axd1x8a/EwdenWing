use std::collections::BTreeMap;
use std::sync::RwLock;

use pelite::pattern;
use pelite::pattern::Atom;
use pelite::pe64::Pe;
use pelite::pe64::PeView;
use retour::static_detour;

struct Game {
    product_names: &'static [&'static str],
    msg_lookup_pattern: &'static [Atom],
    text_embed_image_name_category: u32,
}

static GAMES: &[Game] = &[
    Game {
        product_names: &["DARK SOULS™ III", "DARK SOULS III"],
        msg_lookup_pattern: pattern!("33 d2 ? b8 ? ? 00 00 48 8b cf e8 $ { ' } 48 85 c0"),
        text_embed_image_name_category: 203,
    },
    Game {
        product_names: &["Sekiro™: Shadows Die Twice", "Sekiro: Shadows Die Twice"],
        msg_lookup_pattern: pattern!("48 8b f9 44 8d 42 6d e8 $ { ' } 48 85 c0"),
        text_embed_image_name_category: 203,
    },
    Game {
        product_names: &["ELDEN RING", "ELDEN RING™"],
        msg_lookup_pattern: pattern!("48 8b f9 44 8d 42 6d e8 $ { ' } 48 85 c0"),
        text_embed_image_name_category: 209,
    },
    Game {
        // Idk, I don't have JP version to check exact product name there
        // but ER will not include ™ in JP region for some reason, sooo
        product_names: &[
            "ELDEN RING NIGHTREIGN",
            "ELDEN RING NIGHTREIGN™",
            "ELDEN RING™ NIGHTREIGN",
            "ELDEN RING™ NIGHTREIGN™",
        ],
        msg_lookup_pattern: pattern!("? b8 ? ? 00 00 ? 8b d9 e8 $ { ' } ? 8b c0"),
        text_embed_image_name_category: 209,
    },
    Game {
        // Same as NR
        product_names: &[
            "ARMORED CORE™ VI FIRES OF RUBICON™",
            "ARMORED CORE VI FIRES OF RUBICON",
            "ARMORED CORE™ VI FIRES OF RUBICON",
            "ARMORED CORE VI FIRES OF RUBICON™",
        ],
        msg_lookup_pattern: pattern!("44 8b ca 41 b8 cb 00 00 00 33 d2 e9 $ { ' }"),
        text_embed_image_name_category: 210,
    },
];

unsafe extern "system" {
    #[cfg(debug_assertions)]
    fn AllocConsole() -> i32;
    fn DisableThreadLibraryCalls(hinst: usize);
    fn GetModuleHandleA(lpModuleName: *const u8) -> usize;
    fn MessageBoxW(hWnd: usize, lpText: *const u16, lpCaption: *const u16, uType: u32) -> i32;
}

pub fn show_error_message_box(message: &str, title: &str) {
    let mut message_utf16: Vec<u16> = message.encode_utf16().collect();
    message_utf16.push(0);
    let mut title_utf16: Vec<u16> = title.encode_utf16().collect();
    title_utf16.push(0);

    unsafe {
        MessageBoxW(
            0,
            message_utf16.as_ptr(),
            title_utf16.as_ptr(),
            // MB_ICONERROR | MB_TASKMODAL,
            0x00000010 | 0x00002000,
        );
    }
}

fn panic_hook(panic_info: &std::panic::PanicHookInfo) {
    let message;
    let reason = panic_info.payload().downcast_ref::<&str>();

    if let Some(location) = panic_info.location() {
        message = format!(
            "A panic occurred at {}:{}\nReason: {}",
            location.file(),
            location.line(),
            reason.map_or("Unknown", |v| v),
        );
    } else {
        message = format!(
            "A panic occurred\nReason: {}",
            reason.map_or("Unknown", |v| v)
        );
    }

    show_error_message_box(&message, "Error while loading Ewden Wing");
    std::process::abort();
}

static_detour! {
    static MSG_REPO_LOOKUP_HOOK: unsafe extern "C" fn(usize, u32, u32, u32) -> *const u16;
}

fn get_game_by_product_name(module: &PeView) -> Option<&'static Game> {
    let resources = module.resources().ok()?;
    let info = resources.version_info().ok()?;

    let language = *info.translation().first()?;
    let mut product_name: Option<String> = None;
    info.strings(language, |k, v| {
        if k == "ProductName" {
            product_name = Some(v.to_string());
        }
    });
    let product_name = product_name?;
    GAMES
        .iter()
        .find(|game| game.product_names.iter().any(|&name| product_name == name))
}

fn msg_lookup_hook(this: usize, version: u32, category: u32, id: u32) -> *const u16 {
    static CACHE: RwLock<BTreeMap<(u32, u32, u32), Vec<u16>>> = RwLock::new(BTreeMap::new());

    let key = (version, category, id);
    {
        let cache = CACHE.read().unwrap();
        if let Some(cached_msg) = cache.get(&key) {
            return cached_msg.as_ptr();
        }
    }

    let orig_ptr = unsafe { MSG_REPO_LOOKUP_HOOK.call(this, version, category, id) };
    if orig_ptr.is_null() {
        return orig_ptr;
    }

    let mut len = 0;
    while unsafe { *orig_ptr.add(len) } != 0 {
        len += 1;
    }
    let orig_slice = unsafe { std::slice::from_raw_parts(orig_ptr, len) };
    let utf8_string = String::from_utf16_lossy(orig_slice);

    let tags = find_tags(&utf8_string);
    let escaped = escape_tags(&utf8_string, &tags);
    let mut uwuified = uwuifier::uwuify_str_sse(&escaped)
        .replace(">w<", "^w^")
        .replace(">_<", "w_w");
    uwuified = reinsert_tags(&uwuified, &tags);
    log::info!("Category: {}, ID: {}", category, id);
    log::info!("Original message: {}", utf8_string);
    log::info!("UwUified message: {}", uwuified);

    let uwuified_utf16: Vec<u16> = uwuified.encode_utf16().chain(std::iter::once(0)).collect();

    let mut cache = CACHE.write().unwrap();
    cache.insert(key, uwuified_utf16);
    cache.get(&key).unwrap().as_ptr()
}
type MsgLookupFn = unsafe extern "C" fn(usize, u32, u32, u32) -> *const u16;

fn init() {
    std::panic::set_hook(Box::new(panic_hook));
    #[cfg(debug_assertions)]
    {
        unsafe {
            // AttachConsole(u32::MAX);
            AllocConsole();
        }
        simple_logger::init().unwrap();
    }
    let module_base = unsafe { GetModuleHandleA(std::ptr::null()) as *const u8 };
    let pe = unsafe { PeView::module(module_base) };
    let game =
        get_game_by_product_name(&pe).expect("Could not determine game from module product name");

    let mut matches: [u32; 2] = [0; 2];
    if !pe
        .scanner()
        .matches_code(game.msg_lookup_pattern)
        .next(&mut matches)
    {
        panic!("Could not find MsgRepository lookup function");
    }

    let msg_lookup_va = pe
        .rva_to_va(matches[1])
        .expect("Could not convert MsgRepository lookup RVA to VA");
    let msg_repo_lookup: MsgLookupFn = unsafe { std::mem::transmute(msg_lookup_va as usize) };
    unsafe {
        MSG_REPO_LOOKUP_HOOK
            .initialize(msg_repo_lookup, move |this, version, category, id| {
                if category == game.text_embed_image_name_category {
                    return MSG_REPO_LOOKUP_HOOK.call(this, version, category, id);
                }
                msg_lookup_hook(this, version, category, id)
            })
            .expect("Could not initialize msg lookup hook")
            .enable()
            .expect("Could not enable msg lookup hook");
    }
}

fn find_tags(s: &str) -> Vec<String> {
    use memchr::memmem;

    let bytes = s.as_bytes();
    let mut tags = Vec::new();
    let mut search_start = 0;
    while let Some(start_idx) = memmem::find(&bytes[search_start..], TAG_START) {
        let start = search_start + start_idx;
        if let Some(end_idx) = memmem::find(&bytes[start..], TAG_END) {
            // check if there isn't a '<' between start and end
            if let Some(nested_start_idx) =
                memmem::find(&bytes[start + 1..start + end_idx], TAG_START)
            {
                // found nested tag start, don't consider this a valid tag yet
                search_start = start + 1 + nested_start_idx;
                continue;
            }
            let end = start + end_idx;
            let tag = unsafe { std::str::from_utf8_unchecked(&bytes[start..=end]) };

            tags.push(tag.to_string());

            search_start = end + 1;
        } else {
            break;
        }
    }
    tags
}

const TAG_START: &[u8] = b"<";
const TAG_END: &[u8] = b">";

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

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
/// # Safety
///
/// Safe if called by LoadLibrary
pub unsafe extern "system" fn DllMain(hinst: usize, reason: u32, _reserved: usize) -> bool {
    // DLL_PROCESS_ATTACH
    if reason == 1 {
        unsafe { DisableThreadLibraryCalls(hinst) };
        init();
    };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_tags() {
        let test_str = "Hello <?tag1?> world <?tag2?>! <img src='img://SB_ERR_Blank.png'abc=1/>";
        let tags = find_tags(test_str);
        assert_eq!(
            tags,
            vec![
                "<?tag1?>",
                "<?tag2?>",
                "<img src='img://SB_ERR_Blank.png'abc=1/>"
            ]
        );
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
        let test_str = "Hello <?hello?> world <?world?>! <img src='img://SOMEIMG.png'abc=1/>";
        let tags = find_tags(test_str);
        let escaped = escape_tags(test_str, &tags);
        let mut uwuified = uwuifier::uwuify_str_sse(&escaped)
            .replace(">w<", "^w^")
            .replace(">_<", "w_w");
        uwuified = reinsert_tags(&uwuified, &tags);
        assert_eq!(
            uwuified,
            "Hewwo <?hello?> wowwd <?world?>! <img src='img://SOMEIMG.png'abc=1/>"
        );
    }
}
