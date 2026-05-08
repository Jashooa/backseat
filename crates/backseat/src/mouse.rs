//! Mouse input API.
//!
//! Coordinates are **window-local** (relative to the application's primary
//! surface, origin top-left).  There is no concept of screen-global coordinates
//! for backgrounded apps — use [`Mouse::surface_size`](crate::Mouse::surface_size)
//! to derive coordinates relative to the current logical surface size.

use std::sync::Arc;

use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::error::Error;
use crate::keys::{Axis, Button};
use crate::session::{send_command, Command, Response};

/// Mouse input handle.  Clones share the same IPC connection.
#[derive(Clone)]
pub struct Mouse {
    stream: Arc<Mutex<UnixStream>>,
}

impl Mouse {
    pub(crate) fn new(stream: Arc<Mutex<UnixStream>>) -> Self {
        Self { stream }
    }

    /// Move the cursor to `(x, y)` in window-local pixel coordinates.
    pub async fn move_to(&self, x: f64, y: f64) -> Result<(), Error> {
        self.send(Command {
            ty: "mouse_move".to_string(),
            x: Some(x),
            y: Some(y),
            ..Command::new("mouse_move")
        })
        .await?;
        Ok(())
    }

    /// Move the cursor by `(dx, dy)` relative to its current position.
    ///
    /// # Limitations
    ///
    /// v0.2 does not track the current cursor position, so this is
    /// implemented as a move to the surface centre plus offset.  For precise
    /// relative motion, query [`surface_size`](Self::surface_size) and compute
    /// absolute coordinates yourself.
    pub async fn move_by(&self, _dx: f64, _dy: f64) -> Result<(), Error> {
        Err(Error::SocketError(
            "move_by is not supported in v0.2 — use move_to with surface_size".into(),
        ))
    }

    /// Send a `pressed` followed by `released` event for `button`.
    pub async fn click(&self, button: Button) -> Result<(), Error> {
        self.down(button).await?;
        self.up(button).await
    }

    /// Send two rapid clicks.
    pub async fn double_click(&self, button: Button) -> Result<(), Error> {
        self.click(button).await?;
        self.click(button).await
    }

    /// Send a `pressed` event for `button`.
    pub async fn down(&self, button: Button) -> Result<(), Error> {
        self.send(Command {
            ty: "mouse_button".to_string(),
            button: Some(button.linux_code()),
            state: Some("pressed".to_string()),
            ..Command::new("mouse_button")
        })
        .await?;
        Ok(())
    }

    /// Send a `released` event for `button`.
    pub async fn up(&self, button: Button) -> Result<(), Error> {
        self.send(Command {
            ty: "mouse_button".to_string(),
            button: Some(button.linux_code()),
            state: Some("released".to_string()),
            ..Command::new("mouse_button")
        })
        .await?;
        Ok(())
    }

    /// Scroll `amount` logical units along `axis`.
    pub async fn scroll(&self, axis: Axis, amount: f64) -> Result<(), Error> {
        self.send(Command {
            ty: "scroll".to_string(),
            axis: Some(axis.wayland_axis()),
            value: Some(amount),
            ..Command::new("scroll")
        })
        .await?;
        Ok(())
    }

    /// Return the primary surface's most recent logical `(width, height)`.
    ///
    /// The payload tracks this via intercepted `xdg_toplevel.configure`
    /// events.  If the surface has not yet been configured,
    /// [`Error::ProxyNotFound`](crate::Error::ProxyNotFound) is returned.
    pub async fn surface_size(&self) -> Result<(u32, u32), Error> {
        let resp = self.send(Command::new("surface_size")).await?;
        match (resp.width, resp.height) {
            (Some(w), Some(h)) => Ok((w, h)),
            _ => Err(Error::ProxyNotFound {
                kind: crate::error::ProxyKind::XdgToplevel,
            }),
        }
    }

    async fn send(&self, cmd: Command) -> Result<Response, Error> {
        let mut s = self.stream.lock().await;
        send_command(&mut s, cmd).await
    }
}
