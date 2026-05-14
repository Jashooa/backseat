//! Key, button, and axis enums with Linux input-event-code mappings.
//!
//! These enums are used by the [`Keyboard`](crate::Keyboard) and
//! [`Mouse`](crate::Mouse) APIs to translate high-level identifiers into
//! the low-level codes expected by the Wayland protocol.

use std::fmt;

/// Mouse buttons supported by backseat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Button {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

impl Button {
    /// Linux evdev button code (e.g. `BTN_LEFT` = 0x110).
    pub fn linux_code(self) -> u32 {
        match self {
            Button::Left => 0x110,    // BTN_LEFT
            Button::Right => 0x111,   // BTN_RIGHT
            Button::Middle => 0x112,  // BTN_MIDDLE
            Button::Back => 0x113,    // BTN_SIDE
            Button::Forward => 0x114, // BTN_EXTRA
        }
    }
}

/// Scroll axes supported by backseat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Axis {
    Vertical,
    Horizontal,
}

impl Axis {
    /// Wayland axis identifier (`wl_pointer.axis` value).
    pub fn wayland_axis(self) -> u32 {
        match self {
            Axis::Vertical => 0,
            Axis::Horizontal => 1,
        }
    }
}

/// Keyboard keys supported by backseat.
///
/// The `Raw(u32)` variant allows sending arbitrary Linux keycodes for keys
/// not covered by the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,
    Num0,
    Num1,
    Num2,
    Num3,
    Num4,
    Num5,
    Num6,
    Num7,
    Num8,
    Num9,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    LeftShift,
    RightShift,
    LeftCtrl,
    RightCtrl,
    LeftAlt,
    RightAlt,
    LeftMeta,
    RightMeta,
    Enter,
    Escape,
    Tab,
    Backspace,
    Space,
    CapsLock,
    PrintScreen,
    ScrollLock,
    Pause,
    Minus,
    Equal,
    LeftBrace,
    RightBrace,
    Backslash,
    Semicolon,
    Apostrophe,
    Grave,
    Comma,
    Dot,
    Slash,
    /// Raw Linux keycode fallback.
    Raw(u32),
}

impl Key {
    /// Linux input-event keycode (from `linux/input-event-codes.h`).
    pub fn linux_keycode(self) -> u32 {
        match self {
            Key::A => 30,
            Key::B => 48,
            Key::C => 46,
            Key::D => 32,
            Key::E => 18,
            Key::F => 33,
            Key::G => 34,
            Key::H => 35,
            Key::I => 23,
            Key::J => 36,
            Key::K => 37,
            Key::L => 38,
            Key::M => 50,
            Key::N => 49,
            Key::O => 24,
            Key::P => 25,
            Key::Q => 16,
            Key::R => 19,
            Key::S => 31,
            Key::T => 20,
            Key::U => 22,
            Key::V => 47,
            Key::W => 17,
            Key::X => 45,
            Key::Y => 21,
            Key::Z => 44,
            Key::Num0 => 11,
            Key::Num1 => 2,
            Key::Num2 => 3,
            Key::Num3 => 4,
            Key::Num4 => 5,
            Key::Num5 => 6,
            Key::Num6 => 7,
            Key::Num7 => 8,
            Key::Num8 => 9,
            Key::Num9 => 10,
            Key::F1 => 59,
            Key::F2 => 60,
            Key::F3 => 61,
            Key::F4 => 62,
            Key::F5 => 63,
            Key::F6 => 64,
            Key::F7 => 65,
            Key::F8 => 66,
            Key::F9 => 67,
            Key::F10 => 68,
            Key::F11 => 87,
            Key::F12 => 88,
            Key::Up => 103,
            Key::Down => 108,
            Key::Left => 105,
            Key::Right => 106,
            Key::Home => 102,
            Key::End => 107,
            Key::PageUp => 104,
            Key::PageDown => 109,
            Key::Insert => 110,
            Key::Delete => 111,
            Key::LeftShift => 42,
            Key::RightShift => 54,
            Key::LeftCtrl => 29,
            Key::RightCtrl => 97,
            Key::LeftAlt => 56,
            Key::RightAlt => 100,
            Key::LeftMeta => 125,
            Key::RightMeta => 126,
            Key::Enter => 28,
            Key::Escape => 1,
            Key::Tab => 15,
            Key::Backspace => 14,
            Key::Space => 57,
            Key::CapsLock => 58,
            Key::PrintScreen => 99,
            Key::ScrollLock => 70,
            Key::Pause => 119,
            Key::Minus => 12,
            Key::Equal => 13,
            Key::LeftBrace => 26,
            Key::RightBrace => 27,
            Key::Backslash => 43,
            Key::Semicolon => 39,
            Key::Apostrophe => 40,
            Key::Grave => 41,
            Key::Comma => 51,
            Key::Dot => 52,
            Key::Slash => 53,
            Key::Raw(code) => code,
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::Raw(c) => write!(f, "Raw({})", c),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keycodes() {
        assert_eq!(Key::A.linux_keycode(), 30);
        assert_eq!(Key::Enter.linux_keycode(), 28);
        assert_eq!(Key::Raw(99).linux_keycode(), 99);
    }

    /// Spot-check one key from each family to catch copy-paste errors.
    #[test]
    fn keycodes_spot_check_families() {
        // Arrow keys
        assert_eq!(Key::Up.linux_keycode(), 103);
        assert_eq!(Key::Down.linux_keycode(), 108);
        assert_eq!(Key::Left.linux_keycode(), 105);
        assert_eq!(Key::Right.linux_keycode(), 106);
        // F-keys
        assert_eq!(Key::F1.linux_keycode(), 59);
        assert_eq!(Key::F12.linux_keycode(), 88);
        // Modifiers
        assert_eq!(Key::LeftShift.linux_keycode(), 42);
        assert_eq!(Key::RightShift.linux_keycode(), 54);
        assert_eq!(Key::LeftCtrl.linux_keycode(), 29);
        assert_eq!(Key::RightCtrl.linux_keycode(), 97);
        assert_eq!(Key::LeftAlt.linux_keycode(), 56);
        assert_eq!(Key::RightAlt.linux_keycode(), 100);
        assert_eq!(Key::LeftMeta.linux_keycode(), 125);
        assert_eq!(Key::RightMeta.linux_keycode(), 126);
        // Navigation
        assert_eq!(Key::Home.linux_keycode(), 102);
        assert_eq!(Key::End.linux_keycode(), 107);
        assert_eq!(Key::PageUp.linux_keycode(), 104);
        assert_eq!(Key::PageDown.linux_keycode(), 109);
        assert_eq!(Key::Insert.linux_keycode(), 110);
        assert_eq!(Key::Delete.linux_keycode(), 111);
        // Special
        assert_eq!(Key::Escape.linux_keycode(), 1);
        assert_eq!(Key::Backspace.linux_keycode(), 14);
        assert_eq!(Key::Tab.linux_keycode(), 15);
        assert_eq!(Key::CapsLock.linux_keycode(), 58);
        assert_eq!(Key::PrintScreen.linux_keycode(), 99);
        assert_eq!(Key::ScrollLock.linux_keycode(), 70);
        assert_eq!(Key::Pause.linux_keycode(), 119);
    }

    /// All named Key variants must have unique keycodes — a copy-paste
    /// duplicate would silently map two keys to the same scancode.
    #[test]
    fn keycodes_no_duplicates() {
        use std::collections::HashSet;
        let codes: Vec<u32> = KEY_VARIANTS.iter().map(|k| k.linux_keycode()).collect();
        let unique: HashSet<u32> = codes.iter().copied().collect();
        assert_eq!(
            codes.len(),
            unique.len(),
            "duplicate keycodes found: {:?}",
            {
                let mut seen = HashSet::new();
                codes
                    .iter()
                    .filter(|c| !seen.insert(**c))
                    .copied()
                    .collect::<Vec<u32>>()
            }
        );
    }

    /// A static list of every named Key variant (excluding Raw), used by
    /// the duplicate-detection test above.
    static KEY_VARIANTS: &[Key] = &[
        Key::A,
        Key::B,
        Key::C,
        Key::D,
        Key::E,
        Key::F,
        Key::G,
        Key::H,
        Key::I,
        Key::J,
        Key::K,
        Key::L,
        Key::M,
        Key::N,
        Key::O,
        Key::P,
        Key::Q,
        Key::R,
        Key::S,
        Key::T,
        Key::U,
        Key::V,
        Key::W,
        Key::X,
        Key::Y,
        Key::Z,
        Key::Num0,
        Key::Num1,
        Key::Num2,
        Key::Num3,
        Key::Num4,
        Key::Num5,
        Key::Num6,
        Key::Num7,
        Key::Num8,
        Key::Num9,
        Key::F1,
        Key::F2,
        Key::F3,
        Key::F4,
        Key::F5,
        Key::F6,
        Key::F7,
        Key::F8,
        Key::F9,
        Key::F10,
        Key::F11,
        Key::F12,
        Key::Up,
        Key::Down,
        Key::Left,
        Key::Right,
        Key::Home,
        Key::End,
        Key::PageUp,
        Key::PageDown,
        Key::Insert,
        Key::Delete,
        Key::LeftShift,
        Key::RightShift,
        Key::LeftCtrl,
        Key::RightCtrl,
        Key::LeftAlt,
        Key::RightAlt,
        Key::LeftMeta,
        Key::RightMeta,
        Key::Enter,
        Key::Escape,
        Key::Tab,
        Key::Backspace,
        Key::Space,
        Key::CapsLock,
        Key::PrintScreen,
        Key::ScrollLock,
        Key::Pause,
        Key::Minus,
        Key::Equal,
        Key::LeftBrace,
        Key::RightBrace,
        Key::Backslash,
        Key::Semicolon,
        Key::Apostrophe,
        Key::Grave,
        Key::Comma,
        Key::Dot,
        Key::Slash,
    ];

    #[test]
    fn button_codes() {
        assert_eq!(Button::Left.linux_code(), 0x110);
        assert_eq!(Button::Right.linux_code(), 0x111);
        assert_eq!(Button::Middle.linux_code(), 0x112);
        assert_eq!(Button::Back.linux_code(), 0x113);
        assert_eq!(Button::Forward.linux_code(), 0x114);
    }

    #[test]
    fn axis_codes() {
        assert_eq!(Axis::Vertical.wayland_axis(), 0);
        assert_eq!(Axis::Horizontal.wayland_axis(), 1);
    }

    #[test]
    fn key_display() {
        assert_eq!(Key::A.to_string(), "A");
        assert_eq!(Key::Enter.to_string(), "Enter");
        assert_eq!(Key::Raw(42).to_string(), "Raw(42)");
    }
}
