#import <Cocoa/Cocoa.h>
#include "NativeGlassBackground.h"
#include "SettingsLayout.h"
#include "WindowPresentation.h"
#include "../../../crates/host-macos/include/securelink_client.h"

@interface FlippedDocumentView : NSView
@end
@implementation FlippedDocumentView
- (BOOL)isFlipped { return YES; }
@end

@implementation SettingsInfoTipButton
+ (instancetype)buttonWithTitle:(NSString *)title body:(NSString *)body {
    SettingsInfoTipButton *btn = [[SettingsInfoTipButton alloc] initWithFrame:NSMakeRect(0, 0, 16, 16)];
    btn.translatesAutoresizingMaskIntoConstraints = NO;
    btn.tipTitle = title ?: @"";
    btn.tipBody = body ?: @"";
    btn.bordered = NO;
    btn.bezelStyle = NSBezelStyleCircular;
    btn.buttonType = NSButtonTypeMomentaryPushIn;
    btn.enabled = YES;
    NSImage *icon = [NSImage imageWithSystemSymbolName:@"questionmark.circle"
                              accessibilityDescription:btn.tipTitle];
    if (icon) {
        NSImageSymbolConfiguration *cfg =
            [NSImageSymbolConfiguration configurationWithPointSize:12.0 weight:NSFontWeightRegular];
        btn.image = [icon imageWithSymbolConfiguration:cfg] ?: icon;
        btn.imagePosition = NSImageOnly;
        btn.contentTintColor = [NSColor secondaryLabelColor];
    } else {
        btn.title = @"?";
        btn.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightSemibold];
    }
    btn.toolTip = btn.tipBody;
    [btn setAccessibilityLabel:[NSString stringWithFormat:@"%@的说明：%@", btn.tipTitle, btn.tipBody]];
    btn.target = btn;
    btn.action = @selector(toggleInfoPopover:);
    [NSLayoutConstraint activateConstraints:@[
        [btn.widthAnchor constraintEqualToConstant:16.0],
        [btn.heightAnchor constraintEqualToConstant:16.0],
    ]];
    return btn;
}

- (void)toggleInfoPopover:(id)sender {
    if (self.activePopover.isShown) {
        [self.activePopover performClose:sender];
        return;
    }
    NSPopover *popover = [[NSPopover alloc] init];
    popover.behavior = NSPopoverBehaviorTransient;
    popover.animates = YES;

    NSViewController *vc = [[NSViewController alloc] init];
    NSView *container = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 280, 64)];
    NSTextField *titleField = MSIMEMakeLabel(self.tipTitle, 12.0, NSFontWeightSemibold, [NSColor labelColor]);
    NSTextField *bodyField = [NSTextField wrappingLabelWithString:self.tipBody ?: @""];
    bodyField.translatesAutoresizingMaskIntoConstraints = NO;
    bodyField.font = [NSFont systemFontOfSize:11.5 weight:NSFontWeightRegular];
    bodyField.textColor = [NSColor secondaryLabelColor];
    bodyField.preferredMaxLayoutWidth = 256.0;

    [container addSubview:titleField];
    [container addSubview:bodyField];
    [NSLayoutConstraint activateConstraints:@[
        [titleField.topAnchor constraintEqualToAnchor:container.topAnchor constant:10.0],
        [titleField.leadingAnchor constraintEqualToAnchor:container.leadingAnchor constant:12.0],
        [titleField.trailingAnchor constraintEqualToAnchor:container.trailingAnchor constant:-12.0],
        [bodyField.topAnchor constraintEqualToAnchor:titleField.bottomAnchor constant:4.0],
        [bodyField.leadingAnchor constraintEqualToAnchor:container.leadingAnchor constant:12.0],
        [bodyField.trailingAnchor constraintEqualToAnchor:container.trailingAnchor constant:-12.0],
        [bodyField.bottomAnchor constraintEqualToAnchor:container.bottomAnchor constant:-10.0],
        [container.widthAnchor constraintEqualToConstant:280.0],
    ]];
    vc.view = container;
    popover.contentViewController = vc;
    self.activePopover = popover;
    [popover showRelativeToRect:self.bounds ofView:self preferredEdge:NSRectEdgeMaxY];
}
@end

@interface WorkbenchRootView : NSView
@end
@implementation WorkbenchRootView
- (BOOL)wantsUpdateLayer { return YES; }
- (void)updateLayer {
    self.layer.backgroundColor = [MSIMESettingsSurfaceColor() CGColor];
}
@end

@interface SecureLinkNativeController : NSObject <NSApplicationDelegate, NSWindowDelegate, NSSearchFieldDelegate>
@property (nonatomic, strong) NSWindow *window;
@property (nonatomic, strong) WorkbenchRootView *rootView;
@property (nonatomic, strong) NSView *headerContainer;
@property (nonatomic, strong) NSView *bodyContainer;
@property (nonatomic, strong) NSView *footerContainer;
@property (nonatomic, strong) NSTimer *pollTimer;
@property (nonatomic, strong) NSDictionary *snapshot;
@end

@implementation SecureLinkNativeController

- (NSDictionary *)parseEnvelopeAndExtractValue:(char *)rawCString {
    if (!rawCString) {
        return nil;
    }
    NSData *data = [NSData dataWithBytes:rawCString length:strlen(rawCString)];
    securelink_client_string_free(rawCString);
    NSDictionary *env = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![env isKindOfClass:[NSDictionary class]] || ![env[@"ok"] boolValue]) {
        return nil;
    }
    return env;
}

- (void)dispatchOp:(NSDictionary *)payload {
    NSData *reqData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (!reqData) {
        return;
    }
    char *raw = securelink_client_dispatch((const uint8_t *)reqData.bytes, reqData.length);
    NSDictionary *env = [self parseEnvelopeAndExtractValue:raw];
    if (env && [env[@"value"] isKindOfClass:[NSDictionary class]]) {
        [self applySnapshot:env[@"value"]];
    }
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    char *raw = securelink_client_init_on_main_thread();
    NSDictionary *env = [self parseEnvelopeAndExtractValue:raw];
    NSDictionary *initialSnap = [env[@"value"] isKindOfClass:[NSDictionary class]] ? env[@"value"] : @{};
    self.snapshot = initialSnap;

    BOOL showsDock = initialSnap[@"shows_dock"] ? [initialSnap[@"shows_dock"] boolValue] : YES;
    MSIMEApplyActivationPolicy(showsDock);
    [self setupMainMenu];
    [self setupWindow];
    [self applySnapshot:initialSnap];
    MSIMEPresentWindow(self.window);

    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:0.06
                                                      target:self
                                                    selector:@selector(onPollTimer:)
                                                    userInfo:nil
                                                     repeats:YES];
}

- (void)onPollTimer:(NSTimer *)timer {
    (void)timer;
    char *raw = securelink_client_poll_events();
    if (!raw) {
        return;
    }
    NSDictionary *env = [self parseEnvelopeAndExtractValue:raw];
    if (!env) {
        return;
    }
    if ([env[@"quit"] boolValue]) {
        [self.pollTimer invalidate];
        securelink_client_shutdown();
        [NSApp terminate:nil];
        return;
    }
    if ([env[@"value"] isKindOfClass:[NSDictionary class]]) {
        [self applySnapshot:env[@"value"]];
    }
    if ([env[@"show_window"] boolValue]) {
        MSIMEPresentWindow(self.window);
    }
}

- (void)application:(NSApplication *)application openURLs:(NSArray<NSURL *> *)urls {
    (void)application;
    for (NSURL *url in urls) {
        NSString *abs = url.absoluteString;
        if (abs.length > 0) {
            [self dispatchOp:@{@"op": @"handle_callback_url", @"url": abs}];
        }
    }
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
    (void)sender;
    (void)flag;
    MSIMEPresentWindow(self.window);
    return YES;
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    (void)notification;
    [self.pollTimer invalidate];
    securelink_client_shutdown();
}

- (BOOL)windowShouldClose:(NSWindow *)sender {
    [sender orderOut:nil];
    return NO;
}

- (void)setupMainMenu {
    NSMenu *menubar = [[NSMenu alloc] init];
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    [menubar addItem:appMenuItem];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"荔连"];

    NSMenuItem *showItem = [[NSMenuItem alloc] initWithTitle:@"打开主工作台窗口"
                                                      action:@selector(onMenuShowWindow:)
                                               keyEquivalent:@"1"];
    showItem.target = self;
    [appMenu addItem:showItem];

    NSMenuItem *prefsItem = [[NSMenuItem alloc] initWithTitle:@"偏好设置…"
                                                       action:@selector(onMenuOpenSettings:)
                                                keyEquivalent:@","];
    prefsItem.target = self;
    [appMenu addItem:prefsItem];

    NSMenuItem *updItem = [[NSMenuItem alloc] initWithTitle:@"检查更新…"
                                                     action:@selector(onMenuCheckUpdates:)
                                              keyEquivalent:@"u"];
    updItem.target = self;
    [appMenu addItem:updItem];

    [appMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"退出 荔连"
                                                      action:@selector(onMenuQuit:)
                                               keyEquivalent:@"q"];
    quitItem.target = self;
    [appMenu addItem:quitItem];

    appMenuItem.submenu = appMenu;
    [NSApp setMainMenu:menubar];
}

- (void)setupWindow {
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                       NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;
    NSRect rect = NSMakeRect(0, 0, msime::mac::layout::kWindowWidth, msime::mac::layout::kWindowHeight);
    self.window = [[NSWindow alloc] initWithContentRect:rect
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    self.window.title = @"荔连 · SZU SecureLink";
    self.window.minSize = NSMakeSize(msime::mac::layout::kWindowMinWidth, msime::mac::layout::kWindowMinHeight);
    self.window.delegate = self;
    self.window.releasedWhenClosed = NO;

    self.rootView = [[WorkbenchRootView alloc] initWithFrame:rect];
    self.rootView.wantsLayer = YES;
    self.window.contentView = self.rootView;

    self.headerContainer = [[NSView alloc] initWithFrame:NSZeroRect];
    self.headerContainer.translatesAutoresizingMaskIntoConstraints = NO;
    self.bodyContainer = [[NSView alloc] initWithFrame:NSZeroRect];
    self.bodyContainer.translatesAutoresizingMaskIntoConstraints = NO;
    self.footerContainer = [[NSView alloc] initWithFrame:NSZeroRect];
    self.footerContainer.translatesAutoresizingMaskIntoConstraints = NO;

    [self.rootView addSubview:self.headerContainer];
    [self.rootView addSubview:self.bodyContainer];
    [self.rootView addSubview:self.footerContainer];

    CGFloat margin = msime::mac::layout::kPageMargin;
    [NSLayoutConstraint activateConstraints:@[
        [self.headerContainer.topAnchor constraintEqualToAnchor:self.rootView.topAnchor constant:12.0],
        [self.headerContainer.leadingAnchor constraintEqualToAnchor:self.rootView.leadingAnchor constant:margin],
        [self.headerContainer.trailingAnchor constraintEqualToAnchor:self.rootView.trailingAnchor constant:-margin],
        [self.headerContainer.heightAnchor constraintEqualToConstant:40.0],

        [self.bodyContainer.topAnchor constraintEqualToAnchor:self.headerContainer.bottomAnchor constant:10.0],
        [self.bodyContainer.leadingAnchor constraintEqualToAnchor:self.rootView.leadingAnchor constant:margin],
        [self.bodyContainer.trailingAnchor constraintEqualToAnchor:self.rootView.trailingAnchor constant:-margin],
        [self.bodyContainer.bottomAnchor constraintEqualToAnchor:self.footerContainer.topAnchor constant:-10.0],

        [self.footerContainer.leadingAnchor constraintEqualToAnchor:self.rootView.leadingAnchor constant:margin],
        [self.footerContainer.trailingAnchor constraintEqualToAnchor:self.rootView.trailingAnchor constant:-margin],
        [self.footerContainer.bottomAnchor constraintEqualToAnchor:self.rootView.bottomAnchor constant:-10.0],
        [self.footerContainer.heightAnchor constraintEqualToConstant:26.0],
    ]];

    MSIMEApplySavedWindowFrameOrCenter(self.window);
}

- (NSDictionary *)settingRowForKey:(NSString *)key {
    NSArray *rows = self.snapshot[@"settings_rows"];
    if (![rows isKindOfClass:[NSArray class]]) {
        return @{@"title": key, @"info_tip": @""};
    }
    for (NSDictionary *row in rows) {
        if ([row[@"key"] isEqualToString:key]) {
            return row;
        }
    }
    return @{@"title": key, @"info_tip": @""};
}

- (void)clearSubviews:(NSView *)container {
    for (NSView *sub in [container.subviews copy]) {
        [sub removeFromSuperview];
    }
}

- (void)applySnapshot:(NSDictionary *)snap {
    self.snapshot = snap;
    BOOL showsDock = snap[@"shows_dock"] ? [snap[@"shows_dock"] boolValue] : YES;
    MSIMEApplyActivationPolicy(showsDock);

    BOOL en = [snap[@"locale"] isEqualToString:@"en-US"];
    self.window.title = en ? @"SZU SecureLink · 荔连" : @"荔连 · SZU SecureLink";
    uint32_t accentHex = snap[@"accent_hex"] ? [snap[@"accent_hex"] unsignedIntValue] : 0x8c2232;
    NSColor *accentColor = MSIMEAccentColor(accentHex);

    [self rebuildHeader:snap en:en accentColor:accentColor];
    if ([snap[@"route"] isEqualToString:@"settings"]) {
        [self rebuildSettingsBody:snap en:en accentColor:accentColor];
    } else {
        [self rebuildWorkbenchBody:snap en:en accentColor:accentColor];
    }
    [self rebuildFooter:snap en:en];
}

- (void)rebuildHeader:(NSDictionary *)snap en:(BOOL)en accentColor:(NSColor *)accentColor {
    [self clearSubviews:self.headerContainer];
    NSDictionary *st = [snap[@"status"] isKindOfClass:[NSDictionary class]] ? snap[@"status"] : @{};
    NSString *kind = st[@"kind"] ?: @"disconnected";

    NSImageView *iconView = [[NSImageView alloc] initWithFrame:NSMakeRect(0, 0, 28, 28)];
    iconView.translatesAutoresizingMaskIntoConstraints = NO;
    NSURL *iconURL = [[NSBundle mainBundle] URLForResource:@"AppIcon" withExtension:@"png"];
    NSImage *appImg = iconURL ? [[NSImage alloc] initWithContentsOfURL:iconURL] : [NSApp applicationIconImage];
    iconView.image = appImg;

    NSTextField *titleLabel = MSIMEMakeLabel(
        en ? @"SZU SecureLink · 荔连" : @"荔连 · SZU SecureLink",
        15.0, NSFontWeightBold, accentColor);
    NSTextField *subLabel = MSIMEMakeLabel(
        en ? @"Shenzhen University Zero-Trust Campus Access" : @"深圳大学校园网与常用服务工作台",
        11.5, NSFontWeightRegular, [NSColor secondaryLabelColor]);

    NSColor *badgeColor = accentColor;
    if ([kind isEqualToString:@"connected"]) {
        badgeColor = [NSColor systemGreenColor];
    } else if ([kind isEqualToString:@"connecting"]) {
        badgeColor = [NSColor systemOrangeColor];
    }
    NSTextField *badgeLabel = MSIMEMakeLabel(
        [NSString stringWithFormat:@"● %@", st[@"badge"] ?: @""],
        11.5, NSFontWeightSemibold, badgeColor);

    BOOL inSettings = [snap[@"route"] isEqualToString:@"settings"];
    NSButton *routeBtn = [NSButton buttonWithTitle:(inSettings ? (en ? @"← Workbench" : @"← 返回工作台")
                                                               : (en ? @"Preferences…" : @"偏好设置…"))
                                            target:self
                                            action:@selector(onToggleRoute:)];
    routeBtn.translatesAutoresizingMaskIntoConstraints = NO;
    routeBtn.bezelStyle = NSBezelStyleRounded;
    routeBtn.controlSize = NSControlSizeRegular;

    [self.headerContainer addSubview:iconView];
    [self.headerContainer addSubview:titleLabel];
    [self.headerContainer addSubview:subLabel];
    [self.headerContainer addSubview:badgeLabel];
    [self.headerContainer addSubview:routeBtn];

    [NSLayoutConstraint activateConstraints:@[
        [iconView.leadingAnchor constraintEqualToAnchor:self.headerContainer.leadingAnchor],
        [iconView.centerYAnchor constraintEqualToAnchor:self.headerContainer.centerYAnchor],
        [iconView.widthAnchor constraintEqualToConstant:28.0],
        [iconView.heightAnchor constraintEqualToConstant:28.0],

        [titleLabel.leadingAnchor constraintEqualToAnchor:iconView.trailingAnchor constant:8.0],
        [titleLabel.centerYAnchor constraintEqualToAnchor:self.headerContainer.centerYAnchor],

        [subLabel.leadingAnchor constraintEqualToAnchor:titleLabel.trailingAnchor constant:10.0],
        [subLabel.centerYAnchor constraintEqualToAnchor:self.headerContainer.centerYAnchor],

        [routeBtn.trailingAnchor constraintEqualToAnchor:self.headerContainer.trailingAnchor],
        [routeBtn.centerYAnchor constraintEqualToAnchor:self.headerContainer.centerYAnchor],

        [badgeLabel.trailingAnchor constraintEqualToAnchor:routeBtn.leadingAnchor constant:-12.0],
        [badgeLabel.centerYAnchor constraintEqualToAnchor:self.headerContainer.centerYAnchor],
    ]];
}

- (void)rebuildWorkbenchBody:(NSDictionary *)snap en:(BOOL)en accentColor:(NSColor *)accentColor {
    [self clearSubviews:self.bodyContainer];
    NSDictionary *st = [snap[@"status"] isKindOfClass:[NSDictionary class]] ? snap[@"status"] : @{};
    NSString *kind = st[@"kind"] ?: @"disconnected";

    // Left rail container (252 pt)
    NSView *leftRail = [[NSView alloc] initWithFrame:NSZeroRect];
    leftRail.translatesAutoresizingMaskIntoConstraints = NO;

    // 1. Hero Tunnel Card (`MSIMECardFillColor` + `NSGlassEffectView` on macOS 26+)
    NSBox *heroBox = MSIMEMakeCardBox();
    NSView *heroContent = heroBox.contentView;

    NSTextField *statusTitle = MSIMEMakeLabel(st[@"title"] ?: @"", 13.5, NSFontWeightBold, [NSColor labelColor]);
    SettingsInfoTipButton *statusTip = [SettingsInfoTipButton buttonWithTitle:(st[@"title"] ?: @"校园网隧道")
                                                                         body:(st[@"info_tip"] ?: @"")];
    BOOL showDetails = [snap[@"show_network_details"] boolValue];
    NSString *detailText = st[@"inline_detail"] ?: @"";
    if (showDetails) {
        NSString *iface = [st[@"interface"] isKindOfClass:[NSString class]] ? st[@"interface"] : @"utun (未激活)";
        NSString *vip = [st[@"virtual_ipv4"] isKindOfClass:[NSString class]] ? st[@"virtual_ipv4"] : @"未分配";
        NSString *dns = [st[@"dns_server"] isKindOfClass:[NSString class]] ? st[@"dns_server"] : @"192.168.247.6";
        detailText = [NSString stringWithFormat:@"%@\n接口: %@ · 虚拟 IP: %@\n内网 DNS: %@ · 路由表: 133 条校内网段",
                      detailText, iface, vip, dns];
    }
    NSTextField *inlineDetail = [NSTextField wrappingLabelWithString:detailText];
    inlineDetail.translatesAutoresizingMaskIntoConstraints = NO;
    inlineDetail.font = [NSFont systemFontOfSize:msime::mac::layout::kDetailFontSize weight:NSFontWeightRegular];
    inlineDetail.textColor = [NSColor secondaryLabelColor];
    inlineDetail.preferredMaxLayoutWidth = 220.0;

    NSButton *primaryBtn = [NSButton buttonWithTitle:(st[@"primary_button"] ?: @"连接")
                                              target:self
                                              action:([kind isEqualToString:@"connecting"]
                                                          ? @selector(onDisconnectClicked:)
                                                          : @selector(onToggleConnectClicked:))];
    primaryBtn.translatesAutoresizingMaskIntoConstraints = NO;
    primaryBtn.bezelStyle = NSBezelStyleRounded;
    primaryBtn.controlSize = NSControlSizeLarge;
    primaryBtn.bezelColor = [kind isEqualToString:@"connected"] ? [NSColor systemGreenColor] : accentColor;

    NSButton *repairBtn = [NSButton buttonWithTitle:(en ? @"↻ Auto Repair" : @"↻ 自动修复")
                                             target:self
                                             action:@selector(onRepairClicked:)];
    repairBtn.translatesAutoresizingMaskIntoConstraints = NO;
    repairBtn.bezelStyle = NSBezelStyleRounded;
    repairBtn.controlSize = NSControlSizeSmall;

    NSButton *detailsBtn = [NSButton buttonWithTitle:(showDetails ? (en ? @"▾ Hide Details" : @"▾ 收起详情")
                                                                  : (en ? @"▸ Network Details" : @"▸ 网络详情"))
                                              target:self
                                              action:@selector(onToggleNetworkDetails:)];
    detailsBtn.translatesAutoresizingMaskIntoConstraints = NO;
    detailsBtn.bezelStyle = NSBezelStyleRecessed;
    detailsBtn.bordered = NO;
    detailsBtn.font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightMedium];

    [heroContent addSubview:statusTitle];
    [heroContent addSubview:statusTip];
    [heroContent addSubview:inlineDetail];
    [heroContent addSubview:primaryBtn];
    [heroContent addSubview:detailsBtn];
    [heroContent addSubview:repairBtn];

    [NSLayoutConstraint activateConstraints:@[
        [statusTitle.topAnchor constraintEqualToAnchor:heroContent.topAnchor constant:2.0],
        [statusTitle.leadingAnchor constraintEqualToAnchor:heroContent.leadingAnchor],
        [statusTip.leadingAnchor constraintEqualToAnchor:statusTitle.trailingAnchor constant:6.0],
        [statusTip.centerYAnchor constraintEqualToAnchor:statusTitle.centerYAnchor],
        [statusTip.trailingAnchor constraintLessThanOrEqualToAnchor:heroContent.trailingAnchor],

        [inlineDetail.topAnchor constraintEqualToAnchor:statusTitle.bottomAnchor constant:6.0],
        [inlineDetail.leadingAnchor constraintEqualToAnchor:heroContent.leadingAnchor],
        [inlineDetail.trailingAnchor constraintEqualToAnchor:heroContent.trailingAnchor],

        [primaryBtn.topAnchor constraintEqualToAnchor:inlineDetail.bottomAnchor constant:10.0],
        [primaryBtn.leadingAnchor constraintEqualToAnchor:heroContent.leadingAnchor],
        [primaryBtn.trailingAnchor constraintEqualToAnchor:heroContent.trailingAnchor],

        [detailsBtn.topAnchor constraintEqualToAnchor:primaryBtn.bottomAnchor constant:8.0],
        [detailsBtn.leadingAnchor constraintEqualToAnchor:heroContent.leadingAnchor],
        [detailsBtn.bottomAnchor constraintEqualToAnchor:heroContent.bottomAnchor constant:-2.0],

        [repairBtn.centerYAnchor constraintEqualToAnchor:detailsBtn.centerYAnchor],
        [repairBtn.trailingAnchor constraintEqualToAnchor:heroContent.trailingAnchor],
    ]];

    // 2. Menu Bar Quick Access Card (`MSIMECardFillColor` `NSBox`)
    NSBox *pinsBox = MSIMEMakeCardBox();
    NSView *pinsContent = pinsBox.contentView;
    NSString *pinsTitleText = en ? @"Menu Bar Quick Access (4/4)" : @"菜单栏快捷直达（4 / 4 槽位）";
    NSTextField *pinsTitle = MSIMEMakeLabel(pinsTitleText, msime::mac::layout::kSectionFontSize, NSFontWeightSemibold, [NSColor labelColor]);
    SettingsInfoTipButton *pinsTip = [SettingsInfoTipButton buttonWithTitle:pinsTitleText
                                                                       body:(snap[@"pins_info_tip"] ?: @"")];
    [pinsContent addSubview:pinsTitle];
    [pinsContent addSubview:pinsTip];
    [NSLayoutConstraint activateConstraints:@[
        [pinsTitle.topAnchor constraintEqualToAnchor:pinsContent.topAnchor constant:2.0],
        [pinsTitle.leadingAnchor constraintEqualToAnchor:pinsContent.leadingAnchor],
        [pinsTip.leadingAnchor constraintEqualToAnchor:pinsTitle.trailingAnchor constant:6.0],
        [pinsTip.centerYAnchor constraintEqualToAnchor:pinsTitle.centerYAnchor],
    ]];

    NSView *prevPinAnchor = pinsTitle;
    NSArray *pins = [snap[@"menu_bar_pins"] isKindOfClass:[NSArray class]] ? snap[@"menu_bar_pins"] : @[];
    for (NSUInteger i = 0; i < pins.count; i++) {
        NSDictionary *pin = pins[i];
        NSString *pinTitle = [NSString stringWithFormat:@"%lu. %@", (unsigned long)(i + 1), pin[@"name"] ?: @""];
        NSButton *pinBtn = [NSButton buttonWithTitle:pinTitle target:self action:@selector(onShortcutOpenButton:)];
        pinBtn.translatesAutoresizingMaskIntoConstraints = NO;
        pinBtn.bezelStyle = NSBezelStyleRounded;
        pinBtn.alignment = NSTextAlignmentLeft;
        pinBtn.identifier = pin[@"id"] ?: @"";
        [pinsContent addSubview:pinBtn];
        [NSLayoutConstraint activateConstraints:@[
            [pinBtn.topAnchor constraintEqualToAnchor:prevPinAnchor.bottomAnchor constant:6.0],
            [pinBtn.leadingAnchor constraintEqualToAnchor:pinsContent.leadingAnchor],
            [pinBtn.trailingAnchor constraintEqualToAnchor:pinsContent.trailingAnchor],
            [pinBtn.heightAnchor constraintEqualToConstant:26.0],
        ]];
        prevPinAnchor = pinBtn;
    }
    [prevPinAnchor.bottomAnchor constraintLessThanOrEqualToAnchor:pinsContent.bottomAnchor constant:-4.0].active = YES;

    [leftRail addSubview:heroBox];
    [leftRail addSubview:pinsBox];
    [NSLayoutConstraint activateConstraints:@[
        [leftRail.widthAnchor constraintEqualToConstant:msime::mac::layout::kLeftRailWidth],
        [heroBox.topAnchor constraintEqualToAnchor:leftRail.topAnchor],
        [heroBox.leadingAnchor constraintEqualToAnchor:leftRail.leadingAnchor],
        [heroBox.trailingAnchor constraintEqualToAnchor:leftRail.trailingAnchor],

        [pinsBox.topAnchor constraintEqualToAnchor:heroBox.bottomAnchor constant:msime::mac::layout::kCardSpacing],
        [pinsBox.leadingAnchor constraintEqualToAnchor:leftRail.leadingAnchor],
        [pinsBox.trailingAnchor constraintEqualToAnchor:leftRail.trailingAnchor],
        [pinsBox.bottomAnchor constraintEqualToAnchor:leftRail.bottomAnchor],
    ]];

    // Right Pane: Search Header + Scrollable Categories
    NSBox *rightBox = MSIMEMakeCardBox();
    NSView *rightContent = rightBox.contentView;

    NSTextField *dirTitle = MSIMEMakeLabel(
        en ? @"Campus Services Directory" : @"校内常用服务与学术数据库",
        msime::mac::layout::kSectionFontSize, NSFontWeightSemibold, [NSColor labelColor]);

    NSSearchField *searchField = [[NSSearchField alloc] initWithFrame:NSZeroRect];
    searchField.translatesAutoresizingMaskIntoConstraints = NO;
    searchField.placeholderString = en ? @"Filter services…" : @"搜索校内服务或数据库…";
    searchField.stringValue = snap[@"search_query"] ?: @"";
    searchField.delegate = self;
    searchField.target = self;
    searchField.action = @selector(onSearchFieldChanged:);
    searchField.controlSize = NSControlSizeSmall;

    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSZeroRect];
    scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    scrollView.drawsBackground = NO;
    scrollView.hasVerticalScroller = YES;

    FlippedDocumentView *docView = [[FlippedDocumentView alloc] initWithFrame:NSMakeRect(0, 0, 440, 380)];
    docView.translatesAutoresizingMaskIntoConstraints = NO;
    scrollView.documentView = docView;

    [rightContent addSubview:dirTitle];
    [rightContent addSubview:searchField];
    [rightContent addSubview:scrollView];

    [NSLayoutConstraint activateConstraints:@[
        [dirTitle.topAnchor constraintEqualToAnchor:rightContent.topAnchor constant:2.0],
        [dirTitle.leadingAnchor constraintEqualToAnchor:rightContent.leadingAnchor],
        [searchField.centerYAnchor constraintEqualToAnchor:dirTitle.centerYAnchor],
        [searchField.trailingAnchor constraintEqualToAnchor:rightContent.trailingAnchor],
        [searchField.widthAnchor constraintEqualToConstant:176.0],

        [scrollView.topAnchor constraintEqualToAnchor:dirTitle.bottomAnchor constant:8.0],
        [scrollView.leadingAnchor constraintEqualToAnchor:rightContent.leadingAnchor],
        [scrollView.trailingAnchor constraintEqualToAnchor:rightContent.trailingAnchor],
        [scrollView.bottomAnchor constraintEqualToAnchor:rightContent.bottomAnchor],

        [docView.topAnchor constraintEqualToAnchor:scrollView.contentView.topAnchor],
        [docView.leadingAnchor constraintEqualToAnchor:scrollView.contentView.leadingAnchor],
        [docView.trailingAnchor constraintEqualToAnchor:scrollView.contentView.trailingAnchor],
    ]];

    NSView *prevCatView = nil;
    NSArray *categories = [snap[@"categories"] isKindOfClass:[NSArray class]] ? snap[@"categories"] : @[];
    for (NSDictionary *cat in categories) {
        NSUInteger catIdx = [cat[@"index"] unsignedIntegerValue];
        BOOL collapsed = [cat[@"collapsed"] boolValue];
        NSArray *items = [cat[@"items"] isKindOfClass:[NSArray class]] ? cat[@"items"] : @[];

        NSView *catSection = [[NSView alloc] initWithFrame:NSZeroRect];
        catSection.translatesAutoresizingMaskIntoConstraints = NO;

        NSString *hdrTitle = [NSString stringWithFormat:@"%@ %@ (%lu)",
                              collapsed ? @"▸" : @"▾",
                              cat[@"title"] ?: @"",
                              (unsigned long)items.count];
        NSButton *catBtn = [NSButton buttonWithTitle:hdrTitle target:self action:@selector(onCategoryToggle:)];
        catBtn.translatesAutoresizingMaskIntoConstraints = NO;
        catBtn.bezelStyle = NSBezelStyleRecessed;
        catBtn.tag = (NSInteger)catIdx;
        catBtn.font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold];

        SettingsInfoTipButton *catTip = [SettingsInfoTipButton buttonWithTitle:(cat[@"title"] ?: @"")
                                                                          body:(cat[@"info_tip"] ?: @"")];
        [catSection addSubview:catBtn];
        [catSection addSubview:catTip];
        [NSLayoutConstraint activateConstraints:@[
            [catBtn.topAnchor constraintEqualToAnchor:catSection.topAnchor],
            [catBtn.leadingAnchor constraintEqualToAnchor:catSection.leadingAnchor],
            [catTip.leadingAnchor constraintEqualToAnchor:catBtn.trailingAnchor constant:6.0],
            [catTip.centerYAnchor constraintEqualToAnchor:catBtn.centerYAnchor],
        ]];

        NSView *lastRowAnchor = catBtn;
        if (!collapsed) {
            for (NSDictionary *item in items) {
                NSView *rowView = [[NSView alloc] initWithFrame:NSZeroRect];
                rowView.translatesAutoresizingMaskIntoConstraints = NO;

                NSTextField *nameLbl = MSIMEMakeLabel(item[@"name"] ?: @"", msime::mac::layout::kBodyFontSize, NSFontWeightMedium, [NSColor labelColor]);
                NSTextField *subLbl = MSIMEMakeLabel(item[@"subtitle"] ?: @"", msime::mac::layout::kDetailFontSize, NSFontWeightRegular, [NSColor secondaryLabelColor]);

                BOOL isPinned = [item[@"is_pinned"] boolValue];
                NSButton *pinToggle = [NSButton buttonWithTitle:(isPinned ? (en ? @"Pinned" : @"已固定") : (en ? @"Pin" : @"固定"))
                                                         target:self
                                                         action:@selector(onShortcutPinButton:)];
                pinToggle.translatesAutoresizingMaskIntoConstraints = NO;
                pinToggle.bezelStyle = NSBezelStyleRounded;
                pinToggle.controlSize = NSControlSizeSmall;
                pinToggle.identifier = item[@"id"] ?: @"";

                NSButton *openBtn = [NSButton buttonWithTitle:(en ? @"Open" : @"打开")
                                                       target:self
                                                       action:@selector(onShortcutOpenButton:)];
                openBtn.translatesAutoresizingMaskIntoConstraints = NO;
                openBtn.bezelStyle = NSBezelStyleRounded;
                openBtn.controlSize = NSControlSizeSmall;
                openBtn.identifier = item[@"id"] ?: @"";

                [rowView addSubview:nameLbl];
                [rowView addSubview:subLbl];
                [rowView addSubview:pinToggle];
                [rowView addSubview:openBtn];

                [NSLayoutConstraint activateConstraints:@[
                    [rowView.heightAnchor constraintEqualToConstant:msime::mac::layout::kRowHeight],
                    [nameLbl.leadingAnchor constraintEqualToAnchor:rowView.leadingAnchor constant:8.0],
                    [nameLbl.centerYAnchor constraintEqualToAnchor:rowView.centerYAnchor],
                    [subLbl.leadingAnchor constraintEqualToAnchor:nameLbl.trailingAnchor constant:8.0],
                    [subLbl.centerYAnchor constraintEqualToAnchor:rowView.centerYAnchor],
                    [subLbl.trailingAnchor constraintLessThanOrEqualToAnchor:pinToggle.leadingAnchor constant:-8.0],

                    [openBtn.trailingAnchor constraintEqualToAnchor:rowView.trailingAnchor],
                    [openBtn.centerYAnchor constraintEqualToAnchor:rowView.centerYAnchor],
                    [pinToggle.trailingAnchor constraintEqualToAnchor:openBtn.leadingAnchor constant:-6.0],
                    [pinToggle.centerYAnchor constraintEqualToAnchor:rowView.centerYAnchor],
                ]];

                [catSection addSubview:rowView];
                [NSLayoutConstraint activateConstraints:@[
                    [rowView.topAnchor constraintEqualToAnchor:lastRowAnchor.bottomAnchor constant:4.0],
                    [rowView.leadingAnchor constraintEqualToAnchor:catSection.leadingAnchor],
                    [rowView.trailingAnchor constraintEqualToAnchor:catSection.trailingAnchor],
                ]];
                lastRowAnchor = rowView;
            }
        }
        [lastRowAnchor.bottomAnchor constraintEqualToAnchor:catSection.bottomAnchor constant:-4.0].active = YES;
        [docView addSubview:catSection];
        [NSLayoutConstraint activateConstraints:@[
            [catSection.topAnchor constraintEqualToAnchor:(prevCatView ? prevCatView.bottomAnchor : docView.topAnchor)
                                                 constant:(prevCatView ? 8.0 : 0.0)],
            [catSection.leadingAnchor constraintEqualToAnchor:docView.leadingAnchor],
            [catSection.trailingAnchor constraintEqualToAnchor:docView.trailingAnchor],
        ]];
        prevCatView = catSection;
    }
    if (prevCatView) {
        [prevCatView.bottomAnchor constraintEqualToAnchor:docView.bottomAnchor constant:-8.0].active = YES;
    }

    [self.bodyContainer addSubview:leftRail];
    [self.bodyContainer addSubview:rightBox];
    [NSLayoutConstraint activateConstraints:@[
        [leftRail.topAnchor constraintEqualToAnchor:self.bodyContainer.topAnchor],
        [leftRail.leadingAnchor constraintEqualToAnchor:self.bodyContainer.leadingAnchor],
        [leftRail.bottomAnchor constraintEqualToAnchor:self.bodyContainer.bottomAnchor],

        [rightBox.topAnchor constraintEqualToAnchor:self.bodyContainer.topAnchor],
        [rightBox.leadingAnchor constraintEqualToAnchor:leftRail.trailingAnchor constant:msime::mac::layout::kCardSpacing],
        [rightBox.trailingAnchor constraintEqualToAnchor:self.bodyContainer.trailingAnchor],
        [rightBox.bottomAnchor constraintEqualToAnchor:self.bodyContainer.bottomAnchor],
    ]];
}

// Builds a standard 30pt/38pt native AppKit settings row following `msime`'s `SettingsLayout.h`:
// - Leading: title label + `?` `SettingsInfoTipButton` (static description inside popover)
// - Optional inline detail under title ONLY when `inline_detail` is non-null (live status/values)
// - Trailing: native AppKit control (`NSSwitch`, `NSPopUpButton`, or `NSButton`)
- (NSView *)makeSettingsRowWithKey:(NSString *)key control:(NSView *)control {
    NSDictionary *meta = [self settingRowForKey:key];
    NSString *title = meta[@"title"] ?: key;
    NSString *tip = meta[@"info_tip"] ?: @"";
    id rawInline = meta[@"inline_detail"];
    NSString *inlineDetail = ([rawInline isKindOfClass:[NSString class]] && [rawInline length] > 0) ? rawInline : nil;

    NSView *row = [[NSView alloc] initWithFrame:NSZeroRect];
    row.translatesAutoresizingMaskIntoConstraints = NO;

    NSTextField *titleLbl = MSIMEMakeLabel(title, msime::mac::layout::kBodyFontSize, NSFontWeightMedium, [NSColor labelColor]);
    SettingsInfoTipButton *infoBtn = [SettingsInfoTipButton buttonWithTitle:title body:tip];
    control.translatesAutoresizingMaskIntoConstraints = NO;

    [row addSubview:titleLbl];
    [row addSubview:infoBtn];
    [row addSubview:control];

    CGFloat rowHeight = inlineDetail ? msime::mac::layout::kDetailRowHeight : msime::mac::layout::kRowHeight;
    [NSLayoutConstraint activateConstraints:@[
        [row.heightAnchor constraintEqualToConstant:rowHeight],
        [control.trailingAnchor constraintEqualToAnchor:row.trailingAnchor],
        [control.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
    ]];

    if (inlineDetail) {
        NSTextField *detailLbl = MSIMEMakeLabel(inlineDetail, msime::mac::layout::kDetailFontSize, NSFontWeightRegular, [NSColor secondaryLabelColor]);
        [row addSubview:detailLbl];
        [NSLayoutConstraint activateConstraints:@[
            [titleLbl.topAnchor constraintEqualToAnchor:row.topAnchor constant:2.0],
            [titleLbl.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
            [infoBtn.leadingAnchor constraintEqualToAnchor:titleLbl.trailingAnchor constant:6.0],
            [infoBtn.centerYAnchor constraintEqualToAnchor:titleLbl.centerYAnchor],
            [detailLbl.topAnchor constraintEqualToAnchor:titleLbl.bottomAnchor constant:2.0],
            [detailLbl.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
            [detailLbl.trailingAnchor constraintLessThanOrEqualToAnchor:control.leadingAnchor constant:-12.0],
        ]];
    } else {
        [NSLayoutConstraint activateConstraints:@[
            [titleLbl.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
            [titleLbl.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
            [infoBtn.leadingAnchor constraintEqualToAnchor:titleLbl.trailingAnchor constant:6.0],
            [infoBtn.centerYAnchor constraintEqualToAnchor:titleLbl.centerYAnchor],
            [infoBtn.trailingAnchor constraintLessThanOrEqualToAnchor:control.leadingAnchor constant:-12.0],
        ]];
    }
    return row;
}

- (void)rebuildSettingsBody:(NSDictionary *)snap en:(BOOL)en accentColor:(NSColor *)accentColor {
    (void)accentColor;
    [self clearSubviews:self.bodyContainer];

    // Card 1: System Presence & Startup (`NSPopUpButton` + `NSSwitch`)
    NSBox *presenceCard = MSIMEMakeCardBox();
    NSView *pContent = presenceCard.contentView;

    NSPopUpButton *presencePopup = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    presencePopup.controlSize = NSControlSizeRegular;
    [presencePopup addItemsWithTitles:@[
        en ? @"Dock & Menu Bar (Recommended)" : @"同时显示程序坞与菜单栏图标（推荐）",
        en ? @"Menu Bar Only (Hide Dock)" : @"仅保留右上角菜单栏图标（隐藏 Dock）",
        en ? @"Dock Only (Hide Menu Bar)" : @"仅保留底部程序坞图标（隐藏菜单栏）",
    ]];
    NSString *curPresence = snap[@"shell_presence"] ?: @"dock_and_menubar";
    if ([curPresence isEqualToString:@"menubar_only"]) {
        [presencePopup selectItemAtIndex:1];
    } else if ([curPresence isEqualToString:@"dock_only"]) {
        [presencePopup selectItemAtIndex:2];
    } else {
        [presencePopup selectItemAtIndex:0];
    }
    presencePopup.target = self;
    presencePopup.action = @selector(onPresencePopupChanged:);

    NSSwitch *loginSwitch = [[NSSwitch alloc] initWithFrame:NSZeroRect];
    loginSwitch.controlSize = NSControlSizeSmall;
    loginSwitch.state = [snap[@"launch_at_login"] boolValue] ? NSControlStateValueOn : NSControlStateValueOff;
    loginSwitch.target = self;
    loginSwitch.action = @selector(onLaunchAtLoginToggled:);

    NSView *rPresence = [self makeSettingsRowWithKey:@"shell_presence" control:presencePopup];
    NSView *rLogin = [self makeSettingsRowWithKey:@"launch_at_login" control:loginSwitch];

    // Card 2: Language & Theme Accent (`NSPopUpButton`)
    NSPopUpButton *localePopup = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    [localePopup addItemsWithTitles:@[@"简体中文 (zh-CN)", @"English (en-US)"]];
    [localePopup selectItemAtIndex:(en ? 1 : 0)];
    localePopup.target = self;
    localePopup.action = @selector(onLocalePopupChanged:);

    NSPopUpButton *schemePopup = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    [schemePopup addItemsWithTitles:@[
        en ? @"SZU Lychee Crimson" : @"深大荔枝红（默认）",
        en ? @"Bamboo Academy Green" : @"竹院青",
        en ? @"Pine Indigo" : @"松烟靛",
    ]];
    NSString *curScheme = snap[@"scheme"] ?: @"crimson";
    if ([curScheme isEqualToString:@"bamboo"]) {
        [schemePopup selectItemAtIndex:1];
    } else if ([curScheme isEqualToString:@"indigo"]) {
        [schemePopup selectItemAtIndex:2];
    } else {
        [schemePopup selectItemAtIndex:0];
    }
    schemePopup.target = self;
    schemePopup.action = @selector(onSchemePopupChanged:);

    NSView *rLocale = [self makeSettingsRowWithKey:@"locale" control:localePopup];
    NSView *rScheme = [self makeSettingsRowWithKey:@"scheme" control:schemePopup];

    [pContent addSubview:rPresence];
    [pContent addSubview:rLogin];
    [pContent addSubview:rLocale];
    [pContent addSubview:rScheme];

    [NSLayoutConstraint activateConstraints:@[
        [rPresence.topAnchor constraintEqualToAnchor:pContent.topAnchor constant:2.0],
        [rPresence.leadingAnchor constraintEqualToAnchor:pContent.leadingAnchor],
        [rPresence.trailingAnchor constraintEqualToAnchor:pContent.trailingAnchor],

        [rLogin.topAnchor constraintEqualToAnchor:rPresence.bottomAnchor constant:8.0],
        [rLogin.leadingAnchor constraintEqualToAnchor:pContent.leadingAnchor],
        [rLogin.trailingAnchor constraintEqualToAnchor:pContent.trailingAnchor],

        [rLocale.topAnchor constraintEqualToAnchor:rLogin.bottomAnchor constant:8.0],
        [rLocale.leadingAnchor constraintEqualToAnchor:pContent.leadingAnchor],
        [rLocale.trailingAnchor constraintEqualToAnchor:pContent.trailingAnchor],

        [rScheme.topAnchor constraintEqualToAnchor:rLocale.bottomAnchor constant:8.0],
        [rScheme.leadingAnchor constraintEqualToAnchor:pContent.leadingAnchor],
        [rScheme.trailingAnchor constraintEqualToAnchor:pContent.trailingAnchor],
        [rScheme.bottomAnchor constraintLessThanOrEqualToAnchor:pContent.bottomAnchor constant:-2.0],
    ]];

    // Card 3: Updates & Zero-Trust Helper (inline live status + `NSSwitch` + `NSButton`)
    NSBox *opsCard = MSIMEMakeCardBox();
    NSView *oContent = opsCard.contentView;

    NSButton *checkUpdBtn = [NSButton buttonWithTitle:(en ? @"Check for Updates" : @"立即检查更新")
                                               target:self
                                               action:@selector(onCheckUpdatesClicked:)];
    checkUpdBtn.bezelStyle = NSBezelStyleRounded;

    NSSwitch *autoUpdSwitch = [[NSSwitch alloc] initWithFrame:NSZeroRect];
    autoUpdSwitch.controlSize = NSControlSizeSmall;
    autoUpdSwitch.state = [snap[@"auto_check_updates"] boolValue] ? NSControlStateValueOn : NSControlStateValueOff;
    autoUpdSwitch.target = self;
    autoUpdSwitch.action = @selector(onAutoUpdateToggled:);

    NSButton *repairBtn = [NSButton buttonWithTitle:(en ? @"↻ Reset Routes & DNS" : @"↻ 重置路由与 DNS")
                                             target:self
                                             action:@selector(onRepairClicked:)];
    repairBtn.bezelStyle = NSBezelStyleRounded;

    NSView *rUpdStatus = [self makeSettingsRowWithKey:@"update_status" control:checkUpdBtn];
    NSView *rAutoUpd = [self makeSettingsRowWithKey:@"auto_check_updates" control:autoUpdSwitch];
    NSView *rHelper = [self makeSettingsRowWithKey:@"tunnel_helper" control:repairBtn];

    [oContent addSubview:rUpdStatus];
    [oContent addSubview:rAutoUpd];
    [oContent addSubview:rHelper];

    [NSLayoutConstraint activateConstraints:@[
        [rUpdStatus.topAnchor constraintEqualToAnchor:oContent.topAnchor constant:2.0],
        [rUpdStatus.leadingAnchor constraintEqualToAnchor:oContent.leadingAnchor],
        [rUpdStatus.trailingAnchor constraintEqualToAnchor:oContent.trailingAnchor],

        [rAutoUpd.topAnchor constraintEqualToAnchor:rUpdStatus.bottomAnchor constant:8.0],
        [rAutoUpd.leadingAnchor constraintEqualToAnchor:oContent.leadingAnchor],
        [rAutoUpd.trailingAnchor constraintEqualToAnchor:oContent.trailingAnchor],

        [rHelper.topAnchor constraintEqualToAnchor:rAutoUpd.bottomAnchor constant:8.0],
        [rHelper.leadingAnchor constraintEqualToAnchor:oContent.leadingAnchor],
        [rHelper.trailingAnchor constraintEqualToAnchor:oContent.trailingAnchor],
        [rHelper.bottomAnchor constraintLessThanOrEqualToAnchor:oContent.bottomAnchor constant:-2.0],
    ]];

    [self.bodyContainer addSubview:presenceCard];
    [self.bodyContainer addSubview:opsCard];

    [NSLayoutConstraint activateConstraints:@[
        [presenceCard.topAnchor constraintEqualToAnchor:self.bodyContainer.topAnchor],
        [presenceCard.leadingAnchor constraintEqualToAnchor:self.bodyContainer.leadingAnchor],
        [presenceCard.trailingAnchor constraintEqualToAnchor:self.bodyContainer.trailingAnchor],

        [opsCard.topAnchor constraintEqualToAnchor:presenceCard.bottomAnchor constant:msime::mac::layout::kCardSpacing],
        [opsCard.leadingAnchor constraintEqualToAnchor:self.bodyContainer.leadingAnchor],
        [opsCard.trailingAnchor constraintEqualToAnchor:self.bodyContainer.trailingAnchor],
        [opsCard.bottomAnchor constraintLessThanOrEqualToAnchor:self.bodyContainer.bottomAnchor],
    ]];
}

- (void)rebuildFooter:(NSDictionary *)snap en:(BOOL)en {
    [self clearSubviews:self.footerContainer];
    NSButton *guideBtn = [NSButton buttonWithTitle:(en ? @"Campus Guide" : @"学校使用指南")
                                            target:self
                                            action:@selector(onGuideClicked:)];
    guideBtn.translatesAutoresizingMaskIntoConstraints = NO;
    guideBtn.bezelStyle = NSBezelStyleInline;
    guideBtn.bordered = NO;
    guideBtn.font = [NSFont systemFontOfSize:11.5 weight:NSFontWeightRegular];

    NSTextField *attrLbl = MSIMEMakeLabel(
        snap[@"attribution"] ?: @"深圳大学法律人工智能实训实验室",
        11.5, NSFontWeightRegular, [NSColor secondaryLabelColor]);

    [self.footerContainer addSubview:guideBtn];
    [self.footerContainer addSubview:attrLbl];

    [NSLayoutConstraint activateConstraints:@[
        [guideBtn.leadingAnchor constraintEqualToAnchor:self.footerContainer.leadingAnchor],
        [guideBtn.centerYAnchor constraintEqualToAnchor:self.footerContainer.centerYAnchor],
        [attrLbl.trailingAnchor constraintEqualToAnchor:self.footerContainer.trailingAnchor],
        [attrLbl.centerYAnchor constraintEqualToAnchor:self.footerContainer.centerYAnchor],
    ]];
}

// Actions forwarding directly into the Rust `host_api` JSON dispatcher
- (void)onToggleRoute:(id)sender { (void)sender; [self dispatchOp:@{@"op": @"toggle_settings"}]; }
- (void)onToggleConnectClicked:(id)sender { (void)sender; [self dispatchOp:@{@"op": @"toggle_connect"}]; }
- (void)onDisconnectClicked:(id)sender { (void)sender; [self dispatchOp:@{@"op": @"disconnect"}]; }
- (void)onRepairClicked:(id)sender { (void)sender; [self dispatchOp:@{@"op": @"repair"}]; }
- (void)onToggleNetworkDetails:(id)sender { (void)sender; [self dispatchOp:@{@"op": @"toggle_network_details"}]; }
- (void)onGuideClicked:(id)sender { (void)sender; [self dispatchOp:@{@"op": @"open_guide"}]; }
- (void)onCheckUpdatesClicked:(id)sender { (void)sender; [self dispatchOp:@{@"op": @"check_for_updates"}]; }

- (void)onShortcutOpenButton:(NSButton *)sender {
    NSString *sid = sender.identifier ?: @"";
    if (sid.length > 0) {
        [self dispatchOp:@{@"op": @"activate_shortcut", @"id": sid}];
    }
}

- (void)onShortcutPinButton:(NSButton *)sender {
    NSString *sid = sender.identifier ?: @"";
    if (sid.length > 0) {
        [self dispatchOp:@{@"op": @"toggle_pin", @"id": sid}];
    }
}

- (void)onCategoryToggle:(NSButton *)sender {
    [self dispatchOp:@{@"op": @"toggle_category", @"index": @(sender.tag)}];
}

- (void)onSearchFieldChanged:(NSSearchField *)sender {
    [self dispatchOp:@{@"op": @"set_search_query", @"query": sender.stringValue ?: @""}];
}

- (void)controlTextDidChange:(NSNotification *)obj {
    NSSearchField *field = obj.object;
    if ([field isKindOfClass:[NSSearchField class]]) {
        [self dispatchOp:@{@"op": @"set_search_query", @"query": field.stringValue ?: @""}];
    }
}

- (void)onPresencePopupChanged:(NSPopUpButton *)sender {
    NSInteger idx = sender.indexOfSelectedItem;
    NSString *mode = @"dock_and_menubar";
    if (idx == 1) mode = @"menubar_only";
    else if (idx == 2) mode = @"dock_only";
    [self dispatchOp:@{@"op": @"set_shell_presence", @"mode": mode}];
}

- (void)onLaunchAtLoginToggled:(NSSwitch *)sender {
    BOOL on = (sender.state == NSControlStateValueOn);
    [self dispatchOp:@{@"op": @"set_launch_at_login", @"enabled": @(on)}];
}

- (void)onAutoUpdateToggled:(NSSwitch *)sender {
    BOOL on = (sender.state == NSControlStateValueOn);
    [self dispatchOp:@{@"op": @"set_auto_check_updates", @"enabled": @(on)}];
}

- (void)onLocalePopupChanged:(NSPopUpButton *)sender {
    NSString *loc = (sender.indexOfSelectedItem == 1) ? @"en-US" : @"zh-CN";
    [self dispatchOp:@{@"op": @"set_locale", @"locale": loc}];
}

- (void)onSchemePopupChanged:(NSPopUpButton *)sender {
    NSInteger idx = sender.indexOfSelectedItem;
    NSString *sc = @"crimson";
    if (idx == 1) sc = @"bamboo";
    else if (idx == 2) sc = @"indigo";
    [self dispatchOp:@{@"op": @"set_scheme", @"scheme": sc}];
}

- (void)onMenuShowWindow:(id)sender {
    (void)sender;
    [self dispatchOp:@{@"op": @"set_route", @"route": @"workbench"}];
    MSIMEPresentWindow(self.window);
}
- (void)onMenuOpenSettings:(id)sender {
    (void)sender;
    [self dispatchOp:@{@"op": @"set_route", @"route": @"settings"}];
    MSIMEPresentWindow(self.window);
}
- (void)onMenuCheckUpdates:(id)sender {
    (void)sender;
    [self dispatchOp:@{@"op": @"check_for_updates"}];
    [self dispatchOp:@{@"op": @"set_route", @"route": @"settings"}];
    MSIMEPresentWindow(self.window);
}
- (void)onMenuQuit:(id)sender {
    (void)sender;
    [self.pollTimer invalidate];
    securelink_client_shutdown();
    [NSApp terminate:nil];
}

@end

extern "C" void securelink_macos_run_native_app(void) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        SecureLinkNativeController *delegate = [[SecureLinkNativeController alloc] init];
        app.delegate = delegate;
        [app run];
    }
}
