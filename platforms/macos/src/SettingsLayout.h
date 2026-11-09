#pragma once

#import <Cocoa/Cocoa.h>

namespace msime::mac::layout {
inline constexpr CGFloat kWindowWidth = 760.0;
inline constexpr CGFloat kWindowHeight = 540.0;
inline constexpr CGFloat kWindowMinWidth = 680.0;
inline constexpr CGFloat kWindowMinHeight = 480.0;
inline constexpr CGFloat kLeftRailWidth = 252.0;
inline constexpr CGFloat kRowHeight = 30.0;
inline constexpr CGFloat kDetailRowHeight = 38.0;
inline constexpr CGFloat kBodyFontSize = 13.0;
inline constexpr CGFloat kDetailFontSize = 11.0;
inline constexpr CGFloat kSectionFontSize = 12.0;
inline constexpr CGFloat kCardRadius = 10.0;
inline constexpr CGFloat kCardInsetX = 12.0;
inline constexpr CGFloat kCardInsetY = 8.0;
inline constexpr CGFloat kPageMargin = 18.0;
inline constexpr CGFloat kCardSpacing = 12.0;
} // namespace msime::mac::layout

static inline NSString *MSIMESettingsWindowFrameAutosaveName(void) {
    return @"SZUSecureLinkMainWindow";
}

static inline void MSIMEApplySavedWindowFrameOrCenter(NSWindow *window) {
    NSString *autosaveName = MSIMESettingsWindowFrameAutosaveName();
    NSString *savedKey = [@"NSWindow Frame " stringByAppendingString:autosaveName];
    BOOL hadSavedFrame = [[NSUserDefaults standardUserDefaults] stringForKey:savedKey].length > 0;
    [window setFrameAutosaveName:autosaveName];
    if (!hadSavedFrame) {
        [window center];
    }
}

// Dynamic window surface color (`underPageBackgroundColor` in Aqua so white cards lift off the page;
// `windowBackgroundColor` in Dark Aqua), matching `msime`'s `SettingsLayout.h`.
static inline NSColor *MSIMESettingsSurfaceColor(void) {
    return [NSColor colorWithName:nil dynamicProvider:^NSColor *(NSAppearance *appearance) {
        NSAppearanceName match = [appearance bestMatchFromAppearancesWithNames:@[
            NSAppearanceNameAqua,
            NSAppearanceNameDarkAqua,
        ]];
        if ([match isEqualToString:NSAppearanceNameDarkAqua]) {
            return [NSColor windowBackgroundColor];
        }
        return [NSColor underPageBackgroundColor];
    }];
}

// Dynamic card fill color (`controlBackgroundColor` in Aqua; `windowBackgroundColor` blended 10%
// toward white in Dark Aqua so cards lift without a 1px border), matching `msime`'s `SettingsLayout.h`.
static inline NSColor *MSIMECardFillColor(void) {
    return [NSColor colorWithName:nil dynamicProvider:^NSColor *(NSAppearance *appearance) {
        NSAppearanceName match = [appearance bestMatchFromAppearancesWithNames:@[
            NSAppearanceNameAqua,
            NSAppearanceNameDarkAqua,
        ]];
        if ([match isEqualToString:NSAppearanceNameDarkAqua]) {
            NSColor *base = [[NSColor windowBackgroundColor] colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
            if (base) {
                return [base blendedColorWithFraction:0.10 ofColor:[NSColor whiteColor]] ?: [NSColor controlBackgroundColor];
            }
        }
        return [NSColor controlBackgroundColor];
    }];
}

static inline NSColor *MSIMEAccentColor(uint32_t hex) {
    CGFloat r = ((hex >> 16) & 0xFF) / 255.0;
    CGFloat g = ((hex >> 8) & 0xFF) / 255.0;
    CGFloat b = (hex & 0xFF) / 255.0;
    return [NSColor colorWithSRGBRed:r green:g blue:b alpha:1.0];
}

static inline NSBox *MSIMEMakeCardBox(void) {
    NSBox *box = [[NSBox alloc] initWithFrame:NSZeroRect];
    box.translatesAutoresizingMaskIntoConstraints = NO;
    box.boxType = NSBoxCustom;
    box.borderWidth = 0.0;
    box.cornerRadius = msime::mac::layout::kCardRadius;
    box.fillColor = MSIMECardFillColor();
    box.contentViewMargins = NSMakeSize(msime::mac::layout::kCardInsetX, msime::mac::layout::kCardInsetY);
    return box;
}

static inline NSTextField *MSIMEMakeLabel(NSString *text, CGFloat size, NSFontWeight weight, NSColor *color) {
    NSTextField *label = [NSTextField labelWithString:text ?: @""];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.font = [NSFont systemFontOfSize:size weight:weight];
    label.textColor = color ?: [NSColor labelColor];
    label.lineBreakMode = NSLineBreakByTruncatingTail;
    return label;
}

// Compact 16x16 `?` button that opens an `NSPopover` with static explanatory copy (`info_tip`)
// while keeping the settings/workbench rows free of multi-line paragraph clutter.
// Implements `msime`'s `2026-11-01-settings-descriptions-behind-info-tip.md` specification.
@interface SettingsInfoTipButton : NSButton
@property (nonatomic, copy) NSString *tipTitle;
@property (nonatomic, copy) NSString *tipBody;
@property (nonatomic, strong) NSPopover *activePopover;
+ (instancetype)buttonWithTitle:(NSString *)title body:(NSString *)body;
@end
