#ifndef BACKSEAT_COMMON_H
#define BACKSEAT_COMMON_H

#include <stdint.h>
#include <stdbool.h>

#include "wayland-client.h"
#include "xdg-shell-client-protocol.h"

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

struct app_state;

enum fixture_mode {
    FIXTURE_LISTENER,
    FIXTURE_DISPATCHER,
};

// ---------------------------------------------------------------------------
// State shared across both modes
// ---------------------------------------------------------------------------

struct app_state {
    struct wl_display  *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct xdg_wm_base *wm_base;
    struct wl_seat    *seat;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    struct wl_pointer *pointer;
    struct wl_keyboard *keyboard;

    bool configured;
    bool keyboard_focused;
    bool pointer_focused;
    int width;
    int height;

    enum fixture_mode mode;
};

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

void setup_signals(void);
void allow_same_uid_ptrace(void);
int  connect_and_bind(struct app_state *s);
void request_input_proxies(struct app_state *s);
void try_create_surface(struct app_state *s);
void register_input_proxies(struct app_state *s);

// ---------------------------------------------------------------------------
// Event output (byte-identical to the Rust fixture)
// ---------------------------------------------------------------------------

void print_event(const char *line);

// ---------------------------------------------------------------------------
// Main loop — blocking dispatch
// ---------------------------------------------------------------------------

int run_loop(struct app_state *s);

#endif /* BACKSEAT_COMMON_H */
