#ifndef SECURELINK_CLIENT_H
#define SECURELINK_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Current C ABI version exposed by the Rust host bridge.
uint32_t securelink_client_abi_version(void);

// Initializes the thread-bound Rust WorkbenchWindow + MenuBarBridge session on the main AppKit thread
// and returns the initial UTF-8 JSON envelope (`{"ok":true,"value":...}`).
// The caller owns the returned NUL-terminated buffer and must release it with `securelink_client_string_free`.
char *securelink_client_init_on_main_thread(void);

// Dispatches a UTF-8 JSON request (`{"op":"..."}`) into the active Rust session and returns
// a newly allocated UTF-8 JSON envelope (`{"ok":true,"value":...}` or `{"ok":false,"error":"..."}`).
char *securelink_client_dispatch(const uint8_t *request, size_t length);

// Drains any pending background `SessionEvent`s (tunnel state transitions, menu bar clicks)
// on the main thread. Returns NULL if no events arrived since the last poll, or a newly allocated
// UTF-8 JSON envelope containing `"value"` (the updated snapshot) plus `"show_window"` / `"quit"` flags.
char *securelink_client_poll_events(void);

// Shuts down the menu bar status item and background tunnel supervisor cleanly before app termination.
void securelink_client_shutdown(void);

// Frees a NUL-terminated string previously returned by `securelink_client_*`.
void securelink_client_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif // SECURELINK_CLIENT_H
