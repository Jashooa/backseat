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
#[derive(Clone, Debug)]
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

    /// Send a `modifiers` event with the given depressed modifier bitmask.
    ///
    /// Wayland uses `WL_KEYBOARD_MODIFIER_SHIFT = 0x1` for Shift.
    pub async fn modifiers(&self, depressed: u32) -> Result<(), Error> {
        self.send(Command {
            ty: "modifiers".to_string(),
            depressed: Some(depressed),
            ..Command::new("modifiers")
        })
        .await?;
        Ok(())
    }

    /// Type a string of ASCII characters.
    ///
    /// Each character is converted to a [`Key`] and sent as a tap.  Capital
    /// letters and shifted punctuation automatically synthesise Shift
    /// down/up around the key event.  Non-ASCII characters and unrecognised
    /// punctuation return [`Error::SocketError`](crate::Error::SocketError).
    pub async fn type_text(&self, text: &str) -> Result<(), Error> {
        for ch in text.chars() {
            if !ch.is_ascii() {
                return Err(Error::SocketError(format!(
                    "unsupported non-ASCII character: {ch}"
                )));
            }
            let (key, needs_shift) = ascii_to_key(ch)?;
            if needs_shift {
                self.modifiers(0x1).await?;
                self.down(key).await?;
                self.up(key).await?;
                self.modifiers(0x0).await?;
            } else {
                self.tap(key).await?;
            }
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

/// Convert an ASCII character to the closest [`Key`] variant and whether
/// Shift is required.
///
/// Returns `Err` for characters that have no defined mapping.
fn ascii_to_key(ch: char) -> Result<(Key, bool), Error> {
    match ch {
        'a' => Ok((Key::A, false)),
        'A' => Ok((Key::A, true)),
        'b' => Ok((Key::B, false)),
        'B' => Ok((Key::B, true)),
        'c' => Ok((Key::C, false)),
        'C' => Ok((Key::C, true)),
        'd' => Ok((Key::D, false)),
        'D' => Ok((Key::D, true)),
        'e' => Ok((Key::E, false)),
        'E' => Ok((Key::E, true)),
        'f' => Ok((Key::F, false)),
        'F' => Ok((Key::F, true)),
        'g' => Ok((Key::G, false)),
        'G' => Ok((Key::G, true)),
        'h' => Ok((Key::H, false)),
        'H' => Ok((Key::H, true)),
        'i' => Ok((Key::I, false)),
        'I' => Ok((Key::I, true)),
        'j' => Ok((Key::J, false)),
        'J' => Ok((Key::J, true)),
        'k' => Ok((Key::K, false)),
        'K' => Ok((Key::K, true)),
        'l' => Ok((Key::L, false)),
        'L' => Ok((Key::L, true)),
        'm' => Ok((Key::M, false)),
        'M' => Ok((Key::M, true)),
        'n' => Ok((Key::N, false)),
        'N' => Ok((Key::N, true)),
        'o' => Ok((Key::O, false)),
        'O' => Ok((Key::O, true)),
        'p' => Ok((Key::P, false)),
        'P' => Ok((Key::P, true)),
        'q' => Ok((Key::Q, false)),
        'Q' => Ok((Key::Q, true)),
        'r' => Ok((Key::R, false)),
        'R' => Ok((Key::R, true)),
        's' => Ok((Key::S, false)),
        'S' => Ok((Key::S, true)),
        't' => Ok((Key::T, false)),
        'T' => Ok((Key::T, true)),
        'u' => Ok((Key::U, false)),
        'U' => Ok((Key::U, true)),
        'v' => Ok((Key::V, false)),
        'V' => Ok((Key::V, true)),
        'w' => Ok((Key::W, false)),
        'W' => Ok((Key::W, true)),
        'x' => Ok((Key::X, false)),
        'X' => Ok((Key::X, true)),
        'y' => Ok((Key::Y, false)),
        'Y' => Ok((Key::Y, true)),
        'z' => Ok((Key::Z, false)),
        'Z' => Ok((Key::Z, true)),
        '0' => Ok((Key::Num0, false)),
        '1' => Ok((Key::Num1, false)),
        '2' => Ok((Key::Num2, false)),
        '3' => Ok((Key::Num3, false)),
        '4' => Ok((Key::Num4, false)),
        '5' => Ok((Key::Num5, false)),
        '6' => Ok((Key::Num6, false)),
        '7' => Ok((Key::Num7, false)),
        '8' => Ok((Key::Num8, false)),
        '9' => Ok((Key::Num9, false)),
        ' ' => Ok((Key::Space, false)),
        '\n' => Ok((Key::Enter, false)),
        '\t' => Ok((Key::Tab, false)),
        '-' => Ok((Key::Minus, false)),
        '_' => Ok((Key::Minus, true)),
        '=' => Ok((Key::Equal, false)),
        '+' => Ok((Key::Equal, true)),
        '[' => Ok((Key::LeftBrace, false)),
        '{' => Ok((Key::LeftBrace, true)),
        ']' => Ok((Key::RightBrace, false)),
        '}' => Ok((Key::RightBrace, true)),
        '\\' => Ok((Key::Backslash, false)),
        '|' => Ok((Key::Backslash, true)),
        ';' => Ok((Key::Semicolon, false)),
        ':' => Ok((Key::Semicolon, true)),
        '\'' => Ok((Key::Apostrophe, false)),
        '"' => Ok((Key::Apostrophe, true)),
        '`' => Ok((Key::Grave, false)),
        '~' => Ok((Key::Grave, true)),
        ',' => Ok((Key::Comma, false)),
        '<' => Ok((Key::Comma, true)),
        '.' => Ok((Key::Dot, false)),
        '>' => Ok((Key::Dot, true)),
        '/' => Ok((Key::Slash, false)),
        '?' => Ok((Key::Slash, true)),
        '!' => Ok((Key::Num1, true)),
        '@' => Ok((Key::Num2, true)),
        '#' => Ok((Key::Num3, true)),
        '$' => Ok((Key::Num4, true)),
        '%' => Ok((Key::Num5, true)),
        '^' => Ok((Key::Num6, true)),
        '&' => Ok((Key::Num7, true)),
        '*' => Ok((Key::Num8, true)),
        '(' => Ok((Key::Num9, true)),
        ')' => Ok((Key::Num0, true)),
        _ => Err(Error::SocketError(format!(
            "unsupported ASCII character: {ch}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // ascii_to_key — full character mapping table
    // -------------------------------------------------------------------

    /// Every recognized ASCII character mapping, checked exhaustively.
    /// Format: (character, expected Key, needs_shift).
    #[rustfmt::skip]
    static MAPPINGS: &[(char, Key, bool)] = &[
        // Lowercase letters
        ('a', Key::A, false), ('b', Key::B, false), ('c', Key::C, false),
        ('d', Key::D, false), ('e', Key::E, false), ('f', Key::F, false),
        ('g', Key::G, false), ('h', Key::H, false), ('i', Key::I, false),
        ('j', Key::J, false), ('k', Key::K, false), ('l', Key::L, false),
        ('m', Key::M, false), ('n', Key::N, false), ('o', Key::O, false),
        ('p', Key::P, false), ('q', Key::Q, false), ('r', Key::R, false),
        ('s', Key::S, false), ('t', Key::T, false), ('u', Key::U, false),
        ('v', Key::V, false), ('w', Key::W, false), ('x', Key::X, false),
        ('y', Key::Y, false), ('z', Key::Z, false),
        // Uppercase letters (shift = true)
        ('A', Key::A, true), ('B', Key::B, true), ('C', Key::C, true),
        ('D', Key::D, true), ('E', Key::E, true), ('F', Key::F, true),
        ('G', Key::G, true), ('H', Key::H, true), ('I', Key::I, true),
        ('J', Key::J, true), ('K', Key::K, true), ('L', Key::L, true),
        ('M', Key::M, true), ('N', Key::N, true), ('O', Key::O, true),
        ('P', Key::P, true), ('Q', Key::Q, true), ('R', Key::R, true),
        ('S', Key::S, true), ('T', Key::T, true), ('U', Key::U, true),
        ('V', Key::V, true), ('W', Key::W, true), ('X', Key::X, true),
        ('Y', Key::Y, true), ('Z', Key::Z, true),
        // Digits
        ('0', Key::Num0, false), ('1', Key::Num1, false),
        ('2', Key::Num2, false), ('3', Key::Num3, false),
        ('4', Key::Num4, false), ('5', Key::Num5, false),
        ('6', Key::Num6, false), ('7', Key::Num7, false),
        ('8', Key::Num8, false), ('9', Key::Num9, false),
        // Whitespace
        (' ', Key::Space, false), ('\n', Key::Enter, false), ('\t', Key::Tab, false),
        // Unshifted punctuation
        ('-', Key::Minus, false), ('=', Key::Equal, false),
        ('[', Key::LeftBrace, false), (']', Key::RightBrace, false),
        ('\\', Key::Backslash, false), (';', Key::Semicolon, false),
        ('\'', Key::Apostrophe, false), ('`', Key::Grave, false),
        (',', Key::Comma, false), ('.', Key::Dot, false),
        ('/', Key::Slash, false),
        // Shifted punctuation
        ('_', Key::Minus, true), ('+', Key::Equal, true),
        ('{', Key::LeftBrace, true), ('}', Key::RightBrace, true),
        ('|', Key::Backslash, true), (':', Key::Semicolon, true),
        ('"', Key::Apostrophe, true), ('~', Key::Grave, true),
        ('<', Key::Comma, true), ('>', Key::Dot, true),
        ('?', Key::Slash, true),
        // Shifted digits
        ('!', Key::Num1, true), ('@', Key::Num2, true),
        ('#', Key::Num3, true), ('$', Key::Num4, true),
        ('%', Key::Num5, true), ('^', Key::Num6, true),
        ('&', Key::Num7, true), ('*', Key::Num8, true),
        ('(', Key::Num9, true), (')', Key::Num0, true),
    ];

    #[test]
    fn ascii_to_key_table() {
        for &(ch, expected_key, expected_shift) in MAPPINGS {
            let (key, shift) = ascii_to_key(ch)
                .unwrap_or_else(|e| panic!("ascii_to_key({ch:?}) should succeed, got {e}"));
            assert_eq!(
                key, expected_key,
                "ascii_to_key({ch:?}) key mismatch: got {key:?}, expected {expected_key:?}"
            );
            assert_eq!(
                shift, expected_shift,
                "ascii_to_key({ch:?}) shift mismatch: got {shift}, expected {expected_shift}"
            );
        }
    }

    #[test]
    fn ascii_to_key_all_lowercase() {
        for letter in 'a'..='z' {
            assert!(
                ascii_to_key(letter).is_ok(),
                "lowercase '{letter}' not mapped"
            );
        }
    }

    #[test]
    fn ascii_to_key_unrecognised_unicode() {
        assert!(matches!(
            ascii_to_key('€'),
            Err(Error::SocketError(msg)) if msg.contains("unsupported")
        ));
    }

    #[test]
    fn ascii_to_key_unrecognised_control() {
        // ASCII control characters (0x00–0x1F, except \t and \n) are not mapped.
        for byte in 0u8..=0x1Fu8 {
            let ch = byte as char;
            if ch == '\t' || ch == '\n' {
                continue;
            }
            assert!(
                ascii_to_key(ch).is_err(),
                "control character U+{byte:04X} should be unsupported"
            );
        }
    }
}
