//! backseat-test-fixture — minimal Wayland client for integration tests.
//!
//! Connects to the compositor, creates a toplevel surface, and prints
//! every input event it receives to stdout in a structured format:
//!
//! ```text
//! EVENT: key pressed 30
//! EVENT: key released 30
//! EVENT: button pressed 272
//! EVENT: button released 272
//! EVENT: motion 12800 25600
//! EVENT: keyboard_enter
//! EVENT: pointer_enter 100 200
//! EVENT: ready
//! ```
//!
//! Flushes stdout after every line so the integration test can read
//! events without buffering delays.
//!
//! Exits cleanly on SIGTERM.  On SIGUSR1 prints `EVENT: ready` so the
//! test suite can synchronise between tests when sharing one fixture.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use wayland_client::protocol::{
    wl_compositor, wl_keyboard, wl_pointer, wl_registry, wl_seat, wl_surface,
};
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle};
use wayland_protocols::xdg::shell::client::{xdg_surface, xdg_toplevel, xdg_wm_base};

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);
static RESET_REQUESTED: AtomicBool = AtomicBool::new(false);
static REREGISTER_INPUT: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_: libc::c_int) {
    SHOULD_EXIT.store(true, Ordering::SeqCst);
}

extern "C" fn handle_sigusr1(_: libc::c_int) {
    RESET_REQUESTED.store(true, Ordering::SeqCst);
}

extern "C" fn handle_sigusr2(_: libc::c_int) {
    REREGISTER_INPUT.store(true, Ordering::SeqCst);
}

fn setup_signals() {
    unsafe {
        libc::signal(libc::SIGTERM, handle_sigterm as *const () as usize);
        libc::signal(libc::SIGUSR1, handle_sigusr1 as *const () as usize);
        libc::signal(libc::SIGUSR2, handle_sigusr2 as *const () as usize);
    }
}

/// Print a line to stdout and flush immediately.
fn print_event(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct State {
    compositor: Option<wl_compositor::WlCompositor>,
    wm_base: Option<xdg_wm_base::XdgWmBase>,
    seat: Option<wl_seat::WlSeat>,
    surface: Option<wl_surface::WlSurface>,
    xdg_surface: Option<xdg_surface::XdgSurface>,
    toplevel: Option<xdg_toplevel::XdgToplevel>,
    keyboard: Option<wl_keyboard::WlKeyboard>,
    pointer: Option<wl_pointer::WlPointer>,
    width: i32,
    height: i32,
    configured: bool,
    keyboard_focused: bool,
    pointer_focused: bool,
}

impl State {
    fn new() -> Self {
        Self {
            compositor: None,
            wm_base: None,
            seat: None,
            surface: None,
            xdg_surface: None,
            toplevel: None,
            keyboard: None,
            pointer: None,
            width: 0,
            height: 0,
            configured: false,
            keyboard_focused: false,
            pointer_focused: false,
        }
    }

    /// If we have all required globals, create the surface and toplevel.
    fn try_create_surface(&mut self, qh: &QueueHandle<Self>) {
        if self.configured {
            return;
        }
        let (Some(compositor), Some(wm_base)) = (&self.compositor, &self.wm_base) else {
            return;
        };

        let surface = compositor.create_surface(qh, ());
        let xdg_surface = wm_base.get_xdg_surface(&surface, qh, ());
        let toplevel = xdg_surface.get_toplevel(qh, ());

        // Set a title so the compositor knows what this is.
        toplevel.set_title("backseat-test-fixture".into());

        // Commit so the compositor processes the toplevel creation.
        surface.commit();

        self.surface = Some(surface);
        self.xdg_surface = Some(xdg_surface);
        self.toplevel = Some(toplevel);
    }

    /// Request fresh pointer and keyboard proxies so the payload can
    /// capture them via its hooked `wl_proxy_add_dispatcher`.
    fn force_request_input(&mut self, qh: &QueueHandle<Self>) {
        let Some(seat) = &self.seat else {
            return;
        };
        self.pointer = Some(seat.get_pointer(qh, ()));
        self.keyboard = Some(seat.get_keyboard(qh, ()));
    }
}

// ---------------------------------------------------------------------------
// Wayland dispatch implementations
// ---------------------------------------------------------------------------

impl Dispatch<wl_registry::WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            match &interface[..] {
                "wl_compositor" => {
                    state.compositor = Some(registry.bind::<wl_compositor::WlCompositor, _, _>(
                        name,
                        version.min(4),
                        qh,
                        (),
                    ));
                    state.try_create_surface(qh);
                }
                "xdg_wm_base" => {
                    state.wm_base = Some(registry.bind::<xdg_wm_base::XdgWmBase, _, _>(
                        name,
                        version.min(1),
                        qh,
                        (),
                    ));
                    state.try_create_surface(qh);
                }
                "wl_seat" => {
                    state.seat =
                        Some(registry.bind::<wl_seat::WlSeat, _, _>(name, version.min(5), qh, ()));
                    state.force_request_input(qh);
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<xdg_wm_base::XdgWmBase, ()> for State {
    fn event(
        _: &mut Self,
        wm_base: &xdg_wm_base::XdgWmBase,
        event: xdg_wm_base::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_wm_base::Event::Ping { serial } = event {
            wm_base.pong(serial);
        }
    }
}

impl Dispatch<xdg_surface::XdgSurface, ()> for State {
    fn event(
        state: &mut Self,
        xdg_surface: &xdg_surface::XdgSurface,
        event: xdg_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_surface::Event::Configure { serial } = event {
            xdg_surface.ack_configure(serial);
            if let Some(surface) = &state.surface {
                surface.commit();
            }
        }
    }
}

impl Dispatch<xdg_toplevel::XdgToplevel, ()> for State {
    fn event(
        state: &mut Self,
        _: &xdg_toplevel::XdgToplevel,
        event: xdg_toplevel::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_toplevel::Event::Configure {
            width,
            height,
            states: _,
        } = event
        {
            state.width = width;
            state.height = height;
            state.configured = true;
        }
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn event(
        _state: &mut Self,
        _: &wl_seat::WlSeat,
        _event: wl_seat::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // We request pointer and keyboard unconditionally in try_request_input.
    }
}

impl Dispatch<wl_pointer::WlPointer, ()> for State {
    fn event(
        state: &mut Self,
        _: &wl_pointer::WlPointer,
        event: wl_pointer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_pointer::Event::Enter {
                surface_x,
                surface_y,
                ..
            } => {
                state.pointer_focused = true;
                print_event(&format!("EVENT: pointer_enter {surface_x} {surface_y}"));
            }
            wl_pointer::Event::Leave { .. } => {
                state.pointer_focused = false;
            }
            wl_pointer::Event::Motion {
                surface_x,
                surface_y,
                ..
            } => {
                print_event(&format!("EVENT: motion {surface_x} {surface_y}"));
            }
            wl_pointer::Event::Button {
                button,
                state: btn_state,
                ..
            } => {
                let s = match btn_state {
                    wayland_client::WEnum::Value(v) => match v {
                        wl_pointer::ButtonState::Pressed => "pressed",
                        wl_pointer::ButtonState::Released => "released",
                        _ => "unknown",
                    },
                    wayland_client::WEnum::Unknown(_) => "unknown",
                };
                print_event(&format!("EVENT: button {s} {button}"));
            }
            wl_pointer::Event::Frame => {
                // Wayland 1.10+ frame event — we don't need to print it,
                // the test cares about button/motion events.
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_keyboard::WlKeyboard, ()> for State {
    fn event(
        state: &mut Self,
        _: &wl_keyboard::WlKeyboard,
        event: wl_keyboard::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_keyboard::Event::Enter { .. } => {
                state.keyboard_focused = true;
                print_event("EVENT: keyboard_enter");
            }
            wl_keyboard::Event::Leave { .. } => {
                state.keyboard_focused = false;
            }
            wl_keyboard::Event::Key {
                key,
                state: key_state,
                ..
            } => {
                let s = match key_state {
                    wayland_client::WEnum::Value(v) => match v {
                        wl_keyboard::KeyState::Pressed => "pressed",
                        wl_keyboard::KeyState::Released => "released",
                        _ => "unknown",
                    },
                    wayland_client::WEnum::Unknown(_) => "unknown",
                };
                print_event(&format!("EVENT: key {s} {key}"));
            }
            wl_keyboard::Event::Modifiers {
                mods_depressed,
                mods_latched: _,
                mods_locked: _,
                group: _,
                ..
            } => {
                print_event(&format!("EVENT: modifiers {mods_depressed}"));
            }
            _ => {}
        }
    }
}

// We need dummy Dispatch impls for the objects we don't receive events on.
impl Dispatch<wl_compositor::WlCompositor, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_compositor::WlCompositor,
        _: wl_compositor::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_surface::WlSurface, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_surface::WlSurface,
        _: wl_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    setup_signals();

    let conn = Connection::connect_to_env().expect("Failed to connect to WAYLAND_DISPLAY");
    let mut event_queue: EventQueue<State> = conn.new_event_queue();
    let qh = event_queue.handle();

    let display = conn.display();
    display.get_registry(&qh, ());

    let mut state = State::new();

    // Initial roundtrip to bind globals.
    event_queue.roundtrip(&mut state).expect("roundtrip failed");

    // Wait for the surface to be configured by the compositor.
    let mut attempts = 0;
    while !state.configured && attempts < 200 {
        event_queue
            .blocking_dispatch(&mut state)
            .expect("dispatch failed");
        attempts += 1;
    }

    if !state.configured {
        eprintln!("Fixture: surface never configured — compositor may not support xdg-toplevel");
        std::process::exit(1);
    }

    // Signal that the fixture is ready for input events.
    print_event("EVENT: ready");

    // Main event loop.
    loop {
        if SHOULD_EXIT.load(Ordering::SeqCst) {
            break;
        }

        if RESET_REQUESTED.swap(false, Ordering::SeqCst) {
            // Reset internal state between tests.
            state.keyboard_focused = false;
            state.pointer_focused = false;
            print_event("EVENT: ready");
        }

        if REREGISTER_INPUT.swap(false, Ordering::SeqCst) {
            state.force_request_input(&qh);
        }

        // Non-blocking dispatch with a short timeout so we can check
        // signals and reset requests frequently.
        match event_queue.dispatch_pending(&mut state) {
            Ok(0) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Fixture: dispatch error: {e}");
                break;
            }
        }
    }
}
