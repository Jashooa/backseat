#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

// ---------------------------------------------------------------------------
// Signal handling with self-pipe trick
// ---------------------------------------------------------------------------
// Signal handlers write a single byte to `signal_pipe[1]`.  The main loop
// polls the read end alongside the Wayland display fd so that signals
// are serviced instantly while still allowing the main thread to block —
// which is necessary for the payload's ptrace injection to work reliably.

static volatile sig_atomic_t should_exit      = 0;
static volatile sig_atomic_t reset_requested  = 0;
static volatile sig_atomic_t reregister_input = 0;
static int signal_pipe[2] = { -1, -1 };

static void wake_signal_pipe(void)
{
    char c = 1;
    int saved = errno;
    if (signal_pipe[1] >= 0) {
        (void)write(signal_pipe[1], &c, 1);
    }
    errno = saved;
}

static void handle_sigterm(int sig) { (void)sig; should_exit = 1; wake_signal_pipe(); }
static void handle_sigusr1(int sig) { (void)sig; reset_requested = 1; wake_signal_pipe(); }
static void handle_sigusr2(int sig) { (void)sig; reregister_input = 1; wake_signal_pipe(); }

void setup_signals(void)
{
    if (pipe(signal_pipe) != 0) {
        fprintf(stderr, "Fixture: pipe failed\n");
        signal_pipe[0] = signal_pipe[1] = -1;
        return;
    }
    fcntl(signal_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(signal_pipe[1], F_SETFL, O_NONBLOCK);
    fcntl(signal_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(signal_pipe[1], F_SETFD, FD_CLOEXEC);

    signal(SIGTERM, handle_sigterm);
    signal(SIGUSR1, handle_sigusr1);
    signal(SIGUSR2, handle_sigusr2);
}

/// Drain any bytes in the signal pipe.  Signal flags (set atomically by
/// the handler) are consumed in the main loop.
static void drain_signal_pipe(void)
{
    char buf[32];
    while (signal_pipe[0] >= 0
           && read(signal_pipe[0], buf, sizeof(buf)) > 0) {}
}

void allow_same_uid_ptrace(void)
{
    (void)prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// Forward declarations of listener tables (defined later in this file).
// They are used by registry_global / try_create_surface before the full
// struct definitions appear.
// ---------------------------------------------------------------------------

extern const struct xdg_wm_base_listener xdg_wm_base_listener;
extern const struct xdg_surface_listener xdg_surface_listener;
extern const struct xdg_toplevel_listener xdg_toplevel_listener;
extern const struct wl_seat_listener seat_listener;

// ---------------------------------------------------------------------------
// Event output — flush after every line so the test harness reads without
// buffering delays.  Format must be byte-identical to the Rust fixture.
// ---------------------------------------------------------------------------

void print_event(const char *line)
{
    printf("%s\n", line);
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// Globals — bound through wl_registry
// ---------------------------------------------------------------------------

static void registry_global(void *data,
                            struct wl_registry *registry,
                            uint32_t name,
                            const char *interface,
                            uint32_t version)
{
    struct app_state *s = (struct app_state *)data;

    if (strcmp(interface, "wl_compositor") == 0) {
        s->compositor = wl_registry_bind(registry, name,
                                         &wl_compositor_interface,
                                         version < 4 ? version : 4);
        try_create_surface(s);
    } else if (strcmp(interface, "xdg_wm_base") == 0) {
        s->wm_base = wl_registry_bind(registry, name,
                                      &xdg_wm_base_interface,
                                      version < 1 ? version : 1);
        xdg_wm_base_add_listener(s->wm_base, &xdg_wm_base_listener, s);
        try_create_surface(s);
    } else if (strcmp(interface, "wl_seat") == 0) {
        s->seat = wl_registry_bind(registry, name,
                                   &wl_seat_interface,
                                   version < 5 ? version : 5);
        wl_seat_add_listener(s->seat, &seat_listener, NULL);
        request_input_proxies(s);
    }
}

static void registry_global_remove(void *data,
                                   struct wl_registry *registry,
                                   uint32_t name)
{
    (void)data;
    (void)registry;
    (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global        = registry_global,
    .global_remove = registry_global_remove,
};

int connect_and_bind(struct app_state *s)
{
    s->display = wl_display_connect(NULL);
    if (!s->display) {
        fprintf(stderr, "Fixture: failed to connect to WAYLAND_DISPLAY\n");
        return 1;
    }

    s->registry = wl_display_get_registry(s->display);
    wl_registry_add_listener(s->registry, &registry_listener, s);

    // Roundtrip: send bind requests and process registry globals so
    // that compositor / wm_base / seat / surface / toplevel proxies
    // exist.  After this, callers can register listeners on them.
    wl_display_roundtrip(s->display);
    return 0;
}

// ---------------------------------------------------------------------------
// Request input proxies — called at startup and on SIGUSR2
// ---------------------------------------------------------------------------

void request_input_proxies(struct app_state *s)
{
    if (!s->seat)
        return;

    s->pointer  = wl_seat_get_pointer(s->seat);
    s->keyboard = wl_seat_get_keyboard(s->seat);

    // Send a wl_surface.frame request to expose the surface ID on the wire.
    // The wire-rewrite payload sniffs app→compositor traffic to learn
    // object IDs; a frame request (opcode 3 on a wl_surface) lets the
    // sniffer identify the surface ID.
    if (s->surface) {
        wl_surface_frame(s->surface);
    }

    if (s->mode == FIXTURE_LISTENER) {
        // Listener registration happens later — after the payload
        // hooks wl_proxy_add_listener, it needs to fire again.
        // We just need the proxies to exist; the payload captures
        // them on the next add_listener call.
    } else {
        // Dispatcher registration also happens later via main.c's
        // mode-specific setup.
    }
}

// ---------------------------------------------------------------------------
// Surface / toplevel creation
// ---------------------------------------------------------------------------

void try_create_surface(struct app_state *s)
{
    if (s->configured)
        return;
    if (!s->compositor || !s->wm_base)
        return;

    s->surface = wl_compositor_create_surface(s->compositor);
    s->xdg_surface = xdg_wm_base_get_xdg_surface(s->wm_base, s->surface);
    s->toplevel = xdg_surface_get_toplevel(s->xdg_surface);

    // Register listeners immediately so we catch the configure event
    // that arrives during the next roundtrip / dispatch.
    xdg_surface_add_listener(s->xdg_surface, &xdg_surface_listener, s);
    xdg_toplevel_add_listener(s->toplevel, &xdg_toplevel_listener, s);

    xdg_toplevel_set_title(s->toplevel, "backseat-test-fixture-c");
    wl_surface_commit(s->surface);
}

// ---------------------------------------------------------------------------
// xdg_wm_base listener — handle ping
// ---------------------------------------------------------------------------

static void xdg_wm_base_ping(void *data,
                             struct xdg_wm_base *wm_base,
                             uint32_t serial)
{
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}

const struct xdg_wm_base_listener xdg_wm_base_listener = {
    .ping = xdg_wm_base_ping,
};

// ---------------------------------------------------------------------------
// xdg_surface listener — handle configure
// ---------------------------------------------------------------------------

static void xdg_surface_configure(void *data,
                                  struct xdg_surface *xdg_surface,
                                  uint32_t serial)
{
    (void)data;
    xdg_surface_ack_configure(xdg_surface, serial);
    // Commit any pending surface changes.
    struct app_state *s = (struct app_state *)data;
    if (s->surface)
        wl_surface_commit(s->surface);
}

const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

// ---------------------------------------------------------------------------
// xdg_toplevel listener — track surface size, mark configured
// ---------------------------------------------------------------------------

static void xdg_toplevel_configure(void *data,
                                   struct xdg_toplevel *toplevel,
                                   int32_t width, int32_t height,
                                   struct wl_array *states)
{
    (void)toplevel;
    (void)states;
    struct app_state *s = (struct app_state *)data;
    s->width      = width;
    s->height     = height;
    s->configured = true;
}

static void xdg_toplevel_close(void *data,
                               struct xdg_toplevel *toplevel)
{
    (void)data;
    (void)toplevel;
    should_exit = 1;
}

const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure      = xdg_toplevel_configure,
    .close          = xdg_toplevel_close,
};

// ---------------------------------------------------------------------------
// wl_seat listener — we request input in registry_global, nothing to do here
// ---------------------------------------------------------------------------

static void seat_capabilities(void *data,
                              struct wl_seat *seat,
                              uint32_t caps)
{
    (void)data;
    (void)seat;
    (void)caps;
}

static void seat_name(void *data,
                      struct wl_seat *seat,
                      const char *name)
{
    (void)data;
    (void)seat;
    (void)name;
}

const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name         = seat_name,
};

// ---------------------------------------------------------------------------
// Listener-style input callbacks
// ---------------------------------------------------------------------------

static void pointer_enter(void *data,
                          struct wl_pointer *wl_pointer,
                          uint32_t serial,
                          struct wl_surface *surface,
                          wl_fixed_t surface_x,
                          wl_fixed_t surface_y)
{
    (void)wl_pointer;
    (void)serial;
    (void)surface;
    struct app_state *s = (struct app_state *)data;
    s->pointer_focused = true;
    print_event("EVENT: pointer_enter 0 0");
}

static void pointer_leave(void *data,
                          struct wl_pointer *wl_pointer,
                          uint32_t serial,
                          struct wl_surface *surface)
{
    (void)wl_pointer;
    (void)serial;
    (void)surface;
    struct app_state *s = (struct app_state *)data;
    s->pointer_focused = false;
}

static void pointer_motion(void *data,
                           struct wl_pointer *wl_pointer,
                           uint32_t time,
                           wl_fixed_t surface_x,
                           wl_fixed_t surface_y)
{
    (void)wl_pointer;
    (void)time;
    (void)data;
    printf("EVENT: motion %d %d\n",
           wl_fixed_to_int(surface_x), wl_fixed_to_int(surface_y));
    fflush(stdout);
}

static void pointer_button(void *data,
                           struct wl_pointer *wl_pointer,
                           uint32_t serial,
                           uint32_t time,
                           uint32_t button,
                           uint32_t state)
{
    (void)wl_pointer;
    (void)serial;
    (void)time;
    (void)data;
    const char *s = (state == WL_POINTER_BUTTON_STATE_PRESSED) ? "pressed" : "released";
    printf("EVENT: button %s %u\n", s, button);
    fflush(stdout);
}

static void pointer_axis(void *data,
                         struct wl_pointer *wl_pointer,
                         uint32_t time,
                         uint32_t axis,
                         wl_fixed_t value)
{
    (void)wl_pointer;
    (void)time;
    (void)data;
    const char *a = (axis == WL_POINTER_AXIS_VERTICAL_SCROLL) ? "vertical"
                  : (axis == WL_POINTER_AXIS_HORIZONTAL_SCROLL) ? "horizontal"
                  : "unknown";
    printf("EVENT: axis %s %d\n", a, wl_fixed_to_int(value));
    fflush(stdout);
}

static void pointer_frame(void *data,
                          struct wl_pointer *wl_pointer)
{
    (void)data;
    (void)wl_pointer;
    // Frame events don't need to be printed — the test harness cares
    // about button/motion/axis events.
}

static void pointer_axis_source(void *data,
                                struct wl_pointer *wl_pointer,
                                uint32_t axis_source)
{
    (void)data;
    (void)wl_pointer;
    (void)axis_source;
}

static void pointer_axis_stop(void *data,
                              struct wl_pointer *wl_pointer,
                              uint32_t time,
                              uint32_t axis)
{
    (void)data;
    (void)wl_pointer;
    (void)time;
    (void)axis;
}

static void pointer_axis_discrete(void *data,
                                   struct wl_pointer *wl_pointer,
                                   uint32_t axis,
                                   int32_t discrete)
{
    (void)data;
    (void)wl_pointer;
    (void)axis;
    (void)discrete;
}

static void pointer_axis_relative_direction(void *data,
                                            struct wl_pointer *wl_pointer,
                                            uint32_t axis,
                                            uint32_t direction)
{
    (void)data;
    (void)wl_pointer;
    (void)axis;
    (void)direction;
}

static void pointer_axis_value120(void *data,
                                  struct wl_pointer *wl_pointer,
                                  uint32_t axis,
                                  int32_t value120)
{
    (void)data;
    (void)wl_pointer;
    (void)axis;
    (void)value120;
}

static const struct wl_pointer_listener pointer_listener = {
    .enter                  = pointer_enter,
    .leave                  = pointer_leave,
    .motion                 = pointer_motion,
    .button                 = pointer_button,
    .axis                   = pointer_axis,
    .frame                  = pointer_frame,
    .axis_source            = pointer_axis_source,
    .axis_stop              = pointer_axis_stop,
    .axis_discrete          = pointer_axis_discrete,
    .axis_value120          = pointer_axis_value120,
    .axis_relative_direction = pointer_axis_relative_direction,
};

static void keyboard_keymap(void *data,
                            struct wl_keyboard *wl_keyboard,
                            uint32_t format,
                            int fd,
                            uint32_t size)
{
    (void)data;
    (void)wl_keyboard;
    (void)format;
    if (fd >= 0) close(fd);
    (void)size;
}

static void keyboard_enter(void *data,
                           struct wl_keyboard *wl_keyboard,
                           uint32_t serial,
                           struct wl_surface *surface,
                           struct wl_array *keys)
{
    (void)wl_keyboard;
    (void)serial;
    (void)surface;
    (void)keys;
    struct app_state *s = (struct app_state *)data;
    s->keyboard_focused = true;
    print_event("EVENT: keyboard_enter");
}

static void keyboard_leave(void *data,
                           struct wl_keyboard *wl_keyboard,
                           uint32_t serial,
                           struct wl_surface *surface)
{
    (void)wl_keyboard;
    (void)serial;
    (void)surface;
    struct app_state *s = (struct app_state *)data;
    s->keyboard_focused = false;
}

static void keyboard_key(void *data,
                         struct wl_keyboard *wl_keyboard,
                         uint32_t serial,
                         uint32_t time,
                         uint32_t key,
                         uint32_t state)
{
    (void)wl_keyboard;
    (void)serial;
    (void)time;
    (void)data;
    const char *s = (state == WL_KEYBOARD_KEY_STATE_PRESSED) ? "pressed" : "released";
    printf("EVENT: key %s %u\n", s, key);
    fflush(stdout);
}

static void keyboard_modifiers(void *data,
                               struct wl_keyboard *wl_keyboard,
                               uint32_t serial,
                               uint32_t mods_depressed,
                               uint32_t mods_latched,
                               uint32_t mods_locked,
                               uint32_t group)
{
    (void)wl_keyboard;
    (void)serial;
    (void)mods_latched;
    (void)mods_locked;
    (void)group;
    (void)data;
    printf("EVENT: modifiers %u\n", mods_depressed);
    fflush(stdout);
}

static void keyboard_repeat_info(void *data,
                                  struct wl_keyboard *wl_keyboard,
                                  int32_t rate,
                                  int32_t delay)
{
    (void)data;
    (void)wl_keyboard;
    (void)rate;
    (void)delay;
}

static const struct wl_keyboard_listener keyboard_listener = {
    .keymap      = keyboard_keymap,
    .enter       = keyboard_enter,
    .leave       = keyboard_leave,
    .key         = keyboard_key,
    .modifiers   = keyboard_modifiers,
    .repeat_info = keyboard_repeat_info,
};

// ---------------------------------------------------------------------------
// Dispatcher-style — hand-written dispatcher that decodes wl_argument arrays
// and prints the same EVENT: lines as the listener path.
// ---------------------------------------------------------------------------

static int input_dispatcher(const void *impl, void *proxy,
                            uint32_t opcode,
                            const struct wl_message *msg,
                            union wl_argument *args)
{
    (void)impl;
    (void)msg;

    struct wl_proxy *p = (struct wl_proxy *)proxy;
    const char *iname = wl_proxy_get_interface(p)->name;

    if (strcmp(iname, "wl_pointer") == 0) {
        switch (opcode) {
        case 2: // motion
            printf("EVENT: motion %d %d\n",
                   wl_fixed_to_int(args[1].f),
                   wl_fixed_to_int(args[2].f));
            fflush(stdout);
            break;
        case 3: // button
            printf("EVENT: button %s %u\n",
                   (args[3].u == WL_POINTER_BUTTON_STATE_PRESSED) ? "pressed" : "released",
                   args[2].u);
            fflush(stdout);
            break;
        case 4: // axis
            printf("EVENT: axis %s %d\n",
                   (args[1].u == WL_POINTER_AXIS_VERTICAL_SCROLL) ? "vertical"
                 : (args[1].u == WL_POINTER_AXIS_HORIZONTAL_SCROLL) ? "horizontal"
                 : "unknown",
                   wl_fixed_to_int(args[2].f));
            fflush(stdout);
            break;
        }
    } else if (strcmp(iname, "wl_keyboard") == 0) {
        switch (opcode) {
        case 3: // key
            printf("EVENT: key %s %u\n",
                   (args[3].u == WL_KEYBOARD_KEY_STATE_PRESSED) ? "pressed" : "released",
                   args[2].u);
            fflush(stdout);
            break;
        case 4: // modifiers
            printf("EVENT: modifiers %u\n", args[1].u);
            fflush(stdout);
            break;
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Mode-specific proxy registration — called after bind and on SIGUSR2
// ---------------------------------------------------------------------------

void register_input_proxies(struct app_state *s)
{
    if (!s->pointer || !s->keyboard)
        return;

    if (s->mode == FIXTURE_LISTENER) {
        wl_pointer_add_listener(s->pointer, &pointer_listener, s);
        wl_keyboard_add_listener(s->keyboard, &keyboard_listener, s);
    } else {
        wl_proxy_add_dispatcher((struct wl_proxy *)s->pointer,
                                input_dispatcher,
                                NULL, s);
        wl_proxy_add_dispatcher((struct wl_proxy *)s->keyboard,
                                input_dispatcher,
                                NULL, s);
    }
}

// ---------------------------------------------------------------------------
// Main event loop
// ---------------------------------------------------------------------------

int run_loop(struct app_state *s)
{
    int attempts = 0;

    // Wait for surface configure from the compositor.
    while (!s->configured && attempts < 200) {
        if (wl_display_dispatch(s->display) == -1) {
            fprintf(stderr, "Fixture: dispatch failed while waiting for configure\n");
            return 1;
        }
        attempts++;
    }

    if (!s->configured) {
        fprintf(stderr, "Fixture: surface never configured\n");
        return 1;
    }

    // Register input proxies now that surface is configured.
    // The payload will capture them via the hooked add_dispatcher / add_listener.
    register_input_proxies(s);

    print_event("EVENT: ready");

    // Blocking dispatch with signal-aware poll.  We block the main
    // thread in wl_display_dispatch (injection-safe) but install the
    // signal pipe so we can wake up when signals arrive even if no
    // Wayland events are pending.
    int wayland_fd = wl_display_get_fd(s->display);

    while (!should_exit) {
        // Check / service signal flags at the top of each iteration.
        if (reset_requested) {
            reset_requested = 0;
            s->keyboard_focused = false;
            s->pointer_focused  = false;
            print_event("EVENT: ready");
        }

        if (reregister_input) {
            reregister_input = 0;
            request_input_proxies(s);
            register_input_proxies(s);
        }

        // Drain any events already in the read buffer.  This also
        // triggers the payload's hooks (run_hooks/initial_sweep).
        int rc = wl_display_dispatch_pending(s->display);
        if (rc < 0)
            break;

        // Use the display's internal queue to determine if we need
        // to block.
        while (wl_display_prepare_read(s->display) != 0) {
            if (wl_display_dispatch_pending(s->display) < 0)
                goto break_outer;
        }
        wl_display_flush(s->display);

        struct pollfd fds[2];
        fds[0].fd = wayland_fd;
        fds[0].events = POLLIN;
        fds[1].fd = signal_pipe[0];
        fds[1].events = POLLIN;

        int prc = poll(fds, 2, -1 /* block */);
        if (prc < 0 && errno != EINTR) {
            wl_display_cancel_read(s->display);
            break;
        }

        if (prc > 0 && (fds[0].revents & POLLIN)) {
            // Wayland events arrived — read and dispatch.
            wl_display_read_events(s->display);
            wl_display_dispatch_pending(s->display);
        } else {
            // Signal or timeout — cancel the read.
            wl_display_cancel_read(s->display);
            drain_signal_pipe();
        }
    }
    break_outer:;

    return 0;
}
