//! Exporting a conversation as a Markdown file in the Downloads folder. Uses
//! only the standard library; no dialog or filesystem plugin is exposed to
//! the frontend.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use jarvis_protocol::{ChatRole, ConversationView};

const MAX_TITLE_CHARS: usize = 60;
const MAX_ATTEMPTS: u32 = 200;
const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// `USERPROFILE\Downloads`.
pub fn downloads_dir() -> Result<PathBuf, String> {
    let profile = std::env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "USERPROFILE is not set".to_owned())?;
    let dir = PathBuf::from(profile).join("Downloads");
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(format!("{} does not exist", dir.display()))
    }
}

/// A title that is safe as part of a Windows file name: no path separators
/// or other reserved characters, no control characters, no reserved device
/// names, no trailing dots or spaces, at most 60 characters.
pub fn sanitize_title(title: &str, fallback: &str) -> String {
    let mapped: String = title
        .chars()
        .map(|c| {
            if c.is_control() || is_format(c) || "<>:\"/\\|?*".contains(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let collapsed = mapped.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = collapsed.chars().take(MAX_TITLE_CHARS).collect();
    out = out
        .trim_matches(|c: char| c == '.' || c.is_whitespace())
        .to_owned();
    if out.is_empty() {
        return fallback.to_owned();
    }
    let stem = out.split('.').next().unwrap_or("").to_lowercase();
    if RESERVED.contains(&stem.as_str()) {
        out.insert(0, '_');
    }
    out
}

/// Invisible format characters that could change how a name is displayed:
/// bidirectional controls, zero-width marks, the soft hyphen and the byte
/// order mark.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// `Donna - <title> - <YYYY-MM-DD>.md`, with ` (2)` and so on for `attempt` > 1.
pub fn file_name(title: &str, date: &str, attempt: u32) -> String {
    let title = sanitize_title(title, "Conversa");
    if attempt <= 1 {
        format!("Donna - {title} - {date}.md")
    } else {
        format!("Donna - {title} - {date} ({attempt}).md")
    }
}

/// Today's date (UTC) as `YYYY-MM-DD`.
pub fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() / 86_400);
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!("{year:04}-{month:02}-{day:02}")
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Keep text from being read as HTML: every `<` becomes `&lt;`, inside code
/// too, because a viewer may not agree with a guess about where a code
/// block starts and ends. An entity, unlike `\<`, cannot be undone by a
/// backslash already in the text.
fn escape_line(line: &str) -> String {
    line.replace('<', "&lt;")
}

fn escape_body(text: &str) -> String {
    text.replace("\r\n", "\n")
        .lines()
        .map(escape_line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The conversation as Markdown. Content is plain text; nothing is HTML.
pub fn markdown(view: &ConversationView, english: bool) -> String {
    let (you, donna) = if english {
        ("You", "Donna")
    } else {
        ("Tu", "Donna")
    };
    let title = sanitize_title(
        &view.title,
        if english { "Conversation" } else { "Conversa" },
    );
    let mut out = format!("# {}\n\n", escape_line(&title));
    out.push_str(&format!("_{}_\n", view.created_at));
    for message in &view.messages {
        let who = match message.role {
            ChatRole::User => you,
            ChatRole::Assistant => donna,
        };
        out.push_str(&format!(
            "\n## {who}\n\n{}\n",
            escape_body(&message.content)
        ));
    }
    out
}

/// Write the export without overwriting anything (`create_new`).
pub fn write_unique(dir: &Path, view: &ConversationView, english: bool) -> Result<PathBuf, String> {
    let date = today();
    let body = markdown(view, english);
    for attempt in 1..=MAX_ATTEMPTS {
        let path = dir.join(file_name(&view.title, &date, attempt));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(body.as_bytes())
                    .and_then(|()| file.flush())
                    .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
                return Ok(path);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create {}: {error}", path.display())),
        }
    }
    Err("too many exports with the same name".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_and_reserved_characters_become_spaces() {
        let name = sanitize_title("..\\..\\Windows/System32: a<b>c|d?e*f\"g", "x");
        for bad in ['\\', '/', ':', '<', '>', '|', '?', '*', '"'] {
            assert!(!name.contains(bad), "{name}");
        }
        assert!(!name.starts_with('.'));
        assert_eq!(sanitize_title("a\nb\tc\u{1b}d", "x"), "a b c d");
    }

    #[test]
    fn reserved_device_names_are_prefixed() {
        assert_eq!(sanitize_title("CON", "x"), "_CON");
        assert_eq!(sanitize_title("nul.txt", "x"), "_nul.txt");
        assert_eq!(sanitize_title("COM1", "x"), "_COM1");
        assert_eq!(sanitize_title("console", "x"), "console");
    }

    #[test]
    fn length_dots_and_empty_titles_are_handled() {
        assert_eq!(sanitize_title(&"é".repeat(200), "x").chars().count(), 60);
        assert_eq!(sanitize_title("  title. . ", "x"), "title");
        assert_eq!(sanitize_title("...", "Conversa"), "Conversa");
        assert_eq!(sanitize_title("", "Conversa"), "Conversa");
    }

    #[test]
    fn file_names_follow_the_pattern() {
        assert_eq!(
            file_name("Olá", "2026-10-23", 1),
            "Donna - Olá - 2026-10-23.md"
        );
        assert_eq!(
            file_name("Olá", "2026-10-23", 2),
            "Donna - Olá - 2026-10-23 (2).md"
        );
        assert!(file_name("../x", "2026-10-23", 1).starts_with("Donna - x - "));
    }

    #[test]
    fn dates_are_calendar_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_749), (2026, 10, 23));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn html_is_escaped_everywhere() {
        // An indented fence a viewer does not treat as one must not hide
        // the next line.
        let text = "<script>alert(1)</script>\n```\n<b>code</b>\n```\n    ```\n<img onerror=x>";
        let body = escape_body(text);
        assert!(body.starts_with("&lt;script>"));
        assert!(body.contains("\n&lt;b>code&lt;/b>\n"));
        assert!(body.ends_with("\n&lt;img onerror=x>"));
        // A backslash already before `<` cannot cancel the escape.
        assert_eq!(escape_body("\\<img onerror=x>"), "\\&lt;img onerror=x>");
    }

    #[test]
    fn titles_lose_format_characters() {
        assert_eq!(
            sanitize_title("abc\u{202E}dm.exe\u{200B}", "x"),
            "abc dm.exe"
        );
    }

    #[test]
    fn exports_never_overwrite() {
        let dir = std::env::temp_dir().join(format!("donna-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let view = ConversationView {
            conversation_id: jarvis_protocol::ConversationId::new(),
            title: "Teste".to_owned(),
            created_at: "2026-10-23T10:00:00Z".to_owned(),
            updated_at: "2026-10-23T10:00:00Z".to_owned(),
            messages: Vec::new(),
        };
        let first = write_unique(&dir, &view, false).unwrap();
        let second = write_unique(&dir, &view, false).unwrap();
        assert_ne!(first, second);
        assert!(second.to_string_lossy().contains("(2)"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
