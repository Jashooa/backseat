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
    /// characters and unrecognised punctuation return
    /// [`Error::SocketError`](crate::Error::SocketError).
    pub async fn type_text(&self, text: &str) -> Result<(), Error> {
        for ch in text.chars() {
            if !ch.is_ascii() {
                return Err(Error::SocketError(format!(
                    "unsupported non-ASCII character: {ch}"
                )));
            }
            let key = ascii_to_key(ch)?;
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
/// Returns `Err` for characters that have no defined mapping.
fn ascii_to_key(ch: char) -> Result<Key, Error> {
    match ch {
        'a' | 'A' => Ok(Key::A),
        'b' | 'B' => Ok(Key::B),
        'c' | 'C' => Ok(Key::C),
        'd' | 'D' => Ok(Key::D),
        'e' | 'E' => Ok(Key::E),
        'f' | 'F' => Ok(Key::F),
        'g' | 'G' => Ok(Key::G),
        'h' | 'H' => Ok(Key::H),
        'i' | 'I' => Ok(Key::I),
        'j' | 'J' => Ok(Key::J),
        'k' | 'K' => Ok(Key::K),
        'l' | 'L' => Ok(Key::L),
        'm' | 'M' => Ok(Key::M),
        'n' | 'N' => Ok(Key::N),
        'o' | 'O' => Ok(Key::O),
        'p' | 'P' => Ok(Key::P),
        'q' | 'Q' => Ok(Key::Q),
        'r' | 'R' => Ok(Key::R),
        's' | 'S' => Ok(Key::S),
        't' | 'T' => Ok(Key::T),
        'u' | 'U' => Ok(Key::U),
        'v' | 'V' => Ok(Key::V),
        'w' | 'W' => Ok(Key::W),
        'x' | 'X' => Ok(Key::X),
        'y' | 'Y' => Ok(Key::Y),
        'z' | 'Z' => Ok(Key::Z),
        '0' => Ok(Key::Num0),
        '1' => Ok(Key::Num1),
        '2' => Ok(Key::Num2),
        '3' => Ok(Key::Num3),
        '4' => Ok(Key::Num4),
        '5' => Ok(Key::Num5),
        '6' => Ok(Key::Num6),
        '7' => Ok(Key::Num7),
        '8' => Ok(Key::Num8),
        '9' => Ok(Key::Num9),
        ' ' => Ok(Key::Space),
        '\n' => Ok(Key::Enter),
        '\t' => Ok(Key::Tab),
        '-' => Ok(Key::Minus),
        '=' => Ok(Key::Equal),
        '[' => Ok(Key::LeftBrace),
        ']' => Ok(Key::RightBrace),
        '\\' => Ok(Key::Backslash),
        ';' => Ok(Key::Semicolon),
        '\'' => Ok(Key::Apostrophe),
        '`' => Ok(Key::Grave),
        ',' => Ok(Key::Comma),
        '.' => Ok(Key::Dot),
        '/' => Ok(Key::Slash),
        _ => Err(Error::SocketError(format!(
            "unsupported ASCII character: {ch}"
        ))),
    }
}
