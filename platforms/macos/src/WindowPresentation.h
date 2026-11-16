#pragma once

#import <Cocoa/Cocoa.h>

// Applies the macOS Dock icon visibility policy (`Regular` vs `Accessory`) from Rust's `ShellPresence`.
static inline void SLApplyActivationPolicy(BOOL showsDock) {
    NSApplicationActivationPolicy target = showsDock
        ? NSApplicationActivationPolicyRegular
        : NSApplicationActivationPolicyAccessory;
    if ([NSApp activationPolicy] != target) {
        [NSApp setActivationPolicy:target];
    }
}

// Brings a utility or main window to the foreground on macOS.
static inline void SLPresentWindow(NSWindow *window) {
    if (!window) {
        return;
    }
    if ([NSApp activationPolicy] == NSApplicationActivationPolicyProhibited) {
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    }
    [NSApp activateIgnoringOtherApps:YES];
    [window makeKeyAndOrderFront:nil];
    [window orderFrontRegardless];
}
