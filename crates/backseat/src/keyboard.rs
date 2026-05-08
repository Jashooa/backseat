//! Keyboard input API.
//!
//! All operations send events through the shared IPC connection to the
//! payload, which ultimately calls the target's `wl_keyboard_listener.key`
//! callback on the application's own event thread.

use std::sync::Arc;

use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::error::Error;
use crate::keys::Key;
use crate::session::{send_command, Command, Response};

/// Keyboard input handle.  Clones share the same IPC connection.
#[derive(Clone)]
pub struct Keyboard {
    stream: Arc<Mutex<UnixStream>>,
}

impl Keyboard {
    pub(crate) fn new(stream: Arc<Mutex<UnixStream>>) -> Self {
        Self { stream }
    }

    /// Send a `pressed` followed by `released` event for `key`.
    pub async fn tap(&self, key: Key) -> Result<(), Error> {
        self.down(key).await?;
        self.up(key).await
    }

    /// Send a `pressed` event for `key`.
    pub async fn down(&self, key: Key) -> Result<(), Error> {
        self.send(Command {
            ty: "key".to_string(),
            key: Some(key.linux_keycode()),
            state: Some("pressed".to_string()),
            ..Command::new("key")
        })
        .await?;
        Ok(())
    }

    /// Send a `released` event for `key`.
    pub async fn up(&self, key: Key) -> Result<(), Error> {
        self.send(Command {
            ty: "key".to_string(),
            key: Some(key.linux_keycode()),
            state: Some("released".to_string()),
            ..Command::new("key")
        })
        .await?;
        Ok(())
    }

    /// Type a string of ASCII characters.
    ///
    /// Each character is converted to a [`Key`] and sent as a tap.  Non-ASCII
    /// characters are silently skipped (CJK / IME input requires
    /// `zwp_text_input_v3`, deferred to a later version).
    pub async fn type_text(&self, text: &str) -> Result<(), Error> {
        for ch in text.chars() {
            if !ch.is_ascii() {
                continue;
            }
            let key = ascii_to_key(ch);
            self.tap(key).await?;
        }
        Ok(())
    }

    /// Press all keys simultaneously, then release them in reverse order.
    pub async fn combo(&self, keys: &[Key]) -> Result<(), Error> {
        for &key in keys {
            self.down(key).await?;
        }
        for &key in keys.iter().rev() {
            self.up(key).await?;
        }
        Ok(())
    }

    async fn send(&self, cmd: Command) -> Result<Response, Error> {
        let mut s = self.stream.lock().await;
        send_command(&mut s, cmd).await
    }
}

/// Convert an ASCII character to the closest [`Key`] variant.
///
/// Unrecognised characters map to [`Key::Raw(0)`](crate::Key::Raw).
fn ascii_to_key(ch: char) -> Key {
    match ch {
        'a' | 'A' => Key::A,
        'b' | 'B' => Key::B,
        'c' | 'C' => Key::C,
        'd' | 'D' => Key::D,
        'e' | 'E' => Key::E,
        'f' | 'F' => Key::F,
        'g' | 'G' => Key::G,
        'h' | 'H' => Key::H,
        'i' | 'I' => Key::I,
        'j' | 'J' => Key::J,
        'k' | 'K' => Key::K,
        'l' | 'L' => Key::L,
        'm' | 'M' => Key::M,
        'n' | 'N' => Key::N,
        'o' | 'O' => Key::O,
        'p' | 'P' => Key::P,
        'q' | 'Q' => Key::Q,
        'r' | 'R' => Key::R,
        's' | 'S' => Key::S,
        't' | 'T' => Key::T,
        'u' | 'U' => Key::U,
        'v' | 'V' => Key::V,
        'w' | 'W' => Key::W,
        'x' | 'X' => Key::X,
        'y' | 'Y' => Key::Y,
        'z' | 'Z' => Key::Z,
        '0' => Key::Num0,
        '1' => Key::Num1,
        '2' => Key::Num2,
        '3' => Key::Num3,
        '4' => Key::Num4,
        '5' => Key::Num5,
        '6' => Key::Num6,
        '7' => Key::Num7,
        '8' => Key::Num8,
        '9' => Key::Num9,
        ' ' => Key::Space,
        '\n' => Key::Enter,
        '\t' => Key::Tab,
        '-' => Key::Minus,
        '=' => Key::Equal,
        '[' => Key::LeftBrace,
        ']' => Key::RightBrace,
        '\\' => Key::Backslash,
        ';' => Key::Semicolon,
        '\'' => Key::Apostrophe,
        '`' => Key::Grave,
        ',' => Key::Comma,
        '.' => Key::Dot,
        '/' => Key::Slash,
        _ => Key::Raw(0),
    }
}
