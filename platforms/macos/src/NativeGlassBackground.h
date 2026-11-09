#pragma once

#import <Cocoa/Cocoa.h>
#include <objc/message.h>

// Wraps `content` in `NSGlassEffectView` on macOS 26+ when Reduce Transparency is off,
// matching `metasequoiaime/msime`'s `NativeGlassBackground.h`.
static inline NSView *MSIMEUpdateNativeGlassBackground(NSView *content, CGFloat radius) {
    Class glassClass = NSClassFromString(@"NSGlassEffectView");
    BOOL canUseGlass = (glassClass != Nil) &&
                       ![[NSWorkspace sharedWorkspace] accessibilityDisplayShouldReduceTransparency];
    if (!canUseGlass) {
        content.wantsLayer = YES;
        content.layer.cornerRadius = radius;
        return content;
    }

    NSView *glass = [[glassClass alloc] initWithFrame:content.bounds];
    glass.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    glass.wantsLayer = YES;
    if ([glass respondsToSelector:@selector(setCornerRadius:)]) {
        ((void (*)(id, SEL, CGFloat))objc_msgSend)(glass, @selector(setCornerRadius:), radius);
    }
    if ([glass respondsToSelector:@selector(setContentView:)]) {
        ((void (*)(id, SEL, NSView *))objc_msgSend)(glass, @selector(setContentView:), content);
    } else {
        [glass addSubview:content];
    }
    return glass;
}
