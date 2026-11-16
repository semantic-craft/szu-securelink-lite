#pragma once

#import <Cocoa/Cocoa.h>
#include "SettingsLayout.h"

static inline NSBox *MSIMEMakeVersionPill(NSString *text, NSColor *tintColor) {
    NSBox *pill = [[NSBox alloc] initWithFrame:NSZeroRect];
    pill.translatesAutoresizingMaskIntoConstraints = NO;
    pill.boxType = NSBoxCustom;
    pill.borderWidth = 0.0;
    pill.cornerRadius = 4.0;
    pill.fillColor = [tintColor colorWithAlphaComponent:0.15];
    pill.contentViewMargins = NSMakeSize(6.0, 1.5);
    NSTextField *lbl = MSIMEMakeLabel(text, 10.5, NSFontWeightSemibold, tintColor);
    NSView *content = pill.contentView;
    [content addSubview:lbl];
    [NSLayoutConstraint activateConstraints:@[
        [lbl.topAnchor constraintEqualToAnchor:content.topAnchor],
        [lbl.bottomAnchor constraintEqualToAnchor:content.bottomAnchor],
        [lbl.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [lbl.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
    ]];
    return pill;
}

static inline NSView *MSIMEBuildVersionPageView(
    NSDictionary *snap,
    BOOL en,
    NSColor *accentColor,
    NSView *autoUpdateRow,
    id target,
    SEL checkAction,
    SEL downloadAction,
    SEL releasesAction
) {
    NSDictionary *vp = [snap[@"version_page"] isKindOfClass:[NSDictionary class]] ? snap[@"version_page"] : @{};
    BOOL isChecking = [vp[@"is_checking"] boolValue];
    BOOL hasUpdate = [vp[@"has_update"] boolValue];

    NSView *container = [[NSView alloc] initWithFrame:NSZeroRect];
    container.translatesAutoresizingMaskIntoConstraints = NO;

    // Card 1: Current Version, Update Status, Action Buttons, and Auto-Check Toggle
    NSBox *statusCard = MSIMEMakeCardBox();
    NSView *c1 = statusCard.contentView;

    NSView *topBlock = [[NSView alloc] initWithFrame:NSZeroRect];
    topBlock.translatesAutoresizingMaskIntoConstraints = NO;

    NSImageView *iconView = [[NSImageView alloc] initWithFrame:NSMakeRect(0, 0, 40, 40)];
    iconView.translatesAutoresizingMaskIntoConstraints = NO;
    NSURL *iconURL = [[NSBundle mainBundle] URLForResource:@"AppIcon" withExtension:@"png"];
    iconView.image = iconURL ? [[NSImage alloc] initWithContentsOfURL:iconURL] : [NSApp applicationIconImage];

    NSTextField *titleLbl = MSIMEMakeLabel(vp[@"app_name"] ?: @"荔连 · SZU SecureLink", 14.5, NSFontWeightBold, [NSColor labelColor]);
    [titleLbl setContentHuggingPriority:NSLayoutPriorityDefaultHigh forOrientation:NSLayoutConstraintOrientationHorizontal];
    NSString *verText = [NSString stringWithFormat:@"v%@ (Build %@)", vp[@"version"] ?: @"0.2.3", vp[@"build"] ?: @"4"];
    NSTextField *verLbl = [NSTextField labelWithString:verText];
    verLbl.translatesAutoresizingMaskIntoConstraints = NO;
    verLbl.font = [NSFont monospacedSystemFontOfSize:11.5 weight:NSFontWeightMedium];
    verLbl.textColor = [NSColor secondaryLabelColor];
    [verLbl setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];

    SettingsInfoTipButton *infoBtn = [SettingsInfoTipButton buttonWithTitle:(vp[@"app_name"] ?: @"荔连")
                                                                         body:(vp[@"info_tip"] ?: @"")];

    NSColor *headlineColor = hasUpdate ? [NSColor systemOrangeColor]
                                       : (isChecking ? [NSColor secondaryLabelColor] : [NSColor labelColor]);
    NSTextField *headlineLbl = MSIMEMakeLabel(vp[@"status_headline"] ?: @"", 13.0, NSFontWeightSemibold, headlineColor);

    NSTextField *detailLbl = [NSTextField wrappingLabelWithString:(vp[@"status_detail"] ?: @"")];
    detailLbl.translatesAutoresizingMaskIntoConstraints = NO;
    detailLbl.font = [NSFont systemFontOfSize:11.5 weight:NSFontWeightRegular];
    detailLbl.textColor = [NSColor secondaryLabelColor];
    detailLbl.preferredMaxLayoutWidth = 420.0;
    [detailLbl setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
                                         forOrientation:NSLayoutConstraintOrientationHorizontal];

    NSButton *primaryBtn = [NSButton buttonWithTitle:(vp[@"primary_action_title"] ?: (en ? @"Check for Updates" : @"检查更新"))
                                              target:target
                                              action:(hasUpdate ? downloadAction : checkAction)];
    primaryBtn.translatesAutoresizingMaskIntoConstraints = NO;
    primaryBtn.bezelStyle = NSBezelStyleRounded;
    primaryBtn.controlSize = NSControlSizeRegular;
    if (hasUpdate) {
        primaryBtn.bezelColor = accentColor;
    } else {
        primaryBtn.enabled = !isChecking;
    }
    [primaryBtn setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];
    [primaryBtn setContentCompressionResistancePriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];

    NSButton *releasesBtn = [NSButton buttonWithTitle:(en ? @"Releases ↗" : @"发布页 ↗")
                                               target:target
                                               action:releasesAction];
    releasesBtn.translatesAutoresizingMaskIntoConstraints = NO;
    releasesBtn.bezelStyle = NSBezelStyleRounded;
    releasesBtn.controlSize = NSControlSizeRegular;
    [releasesBtn setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];
    [releasesBtn setContentCompressionResistancePriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];

    [topBlock addSubview:iconView];
    [topBlock addSubview:titleLbl];
    [topBlock addSubview:verLbl];
    [topBlock addSubview:infoBtn];
    [topBlock addSubview:headlineLbl];
    [topBlock addSubview:detailLbl];
    [topBlock addSubview:primaryBtn];
    [topBlock addSubview:releasesBtn];

    [NSLayoutConstraint activateConstraints:@[
        [iconView.leadingAnchor constraintEqualToAnchor:topBlock.leadingAnchor],
        [iconView.topAnchor constraintEqualToAnchor:topBlock.topAnchor constant:2.0],
        [iconView.widthAnchor constraintEqualToConstant:40.0],
        [iconView.heightAnchor constraintEqualToConstant:40.0],
        [iconView.bottomAnchor constraintLessThanOrEqualToAnchor:topBlock.bottomAnchor],

        [releasesBtn.trailingAnchor constraintEqualToAnchor:topBlock.trailingAnchor],
        [releasesBtn.centerYAnchor constraintEqualToAnchor:topBlock.centerYAnchor],
        [primaryBtn.trailingAnchor constraintEqualToAnchor:releasesBtn.leadingAnchor constant:-8.0],
        [primaryBtn.centerYAnchor constraintEqualToAnchor:topBlock.centerYAnchor],

        [titleLbl.topAnchor constraintEqualToAnchor:topBlock.topAnchor],
        [titleLbl.leadingAnchor constraintEqualToAnchor:iconView.trailingAnchor constant:12.0],
        [verLbl.leadingAnchor constraintEqualToAnchor:titleLbl.trailingAnchor constant:8.0],
        [verLbl.firstBaselineAnchor constraintEqualToAnchor:titleLbl.firstBaselineAnchor],
        [infoBtn.leadingAnchor constraintEqualToAnchor:verLbl.trailingAnchor constant:6.0],
        [infoBtn.centerYAnchor constraintEqualToAnchor:titleLbl.centerYAnchor],
        [infoBtn.trailingAnchor constraintLessThanOrEqualToAnchor:primaryBtn.leadingAnchor constant:-12.0],

        [headlineLbl.topAnchor constraintEqualToAnchor:titleLbl.bottomAnchor constant:4.0],
        [headlineLbl.leadingAnchor constraintEqualToAnchor:titleLbl.leadingAnchor],
        [headlineLbl.trailingAnchor constraintLessThanOrEqualToAnchor:primaryBtn.leadingAnchor constant:-12.0],

        [detailLbl.topAnchor constraintEqualToAnchor:headlineLbl.bottomAnchor constant:3.0],
        [detailLbl.leadingAnchor constraintEqualToAnchor:titleLbl.leadingAnchor],
        [detailLbl.trailingAnchor constraintLessThanOrEqualToAnchor:primaryBtn.leadingAnchor constant:-12.0],
        [detailLbl.bottomAnchor constraintEqualToAnchor:topBlock.bottomAnchor],
    ]];

    NSBox *sep = [[NSBox alloc] initWithFrame:NSZeroRect];
    sep.translatesAutoresizingMaskIntoConstraints = NO;
    sep.boxType = NSBoxSeparator;

    [c1 addSubview:topBlock];
    [c1 addSubview:sep];
    [c1 addSubview:autoUpdateRow];

    [NSLayoutConstraint activateConstraints:@[
        [topBlock.topAnchor constraintEqualToAnchor:c1.topAnchor constant:2.0],
        [topBlock.leadingAnchor constraintEqualToAnchor:c1.leadingAnchor],
        [topBlock.trailingAnchor constraintEqualToAnchor:c1.trailingAnchor],

        [sep.topAnchor constraintEqualToAnchor:topBlock.bottomAnchor constant:10.0],
        [sep.leadingAnchor constraintEqualToAnchor:c1.leadingAnchor],
        [sep.trailingAnchor constraintEqualToAnchor:c1.trailingAnchor],

        [autoUpdateRow.topAnchor constraintEqualToAnchor:sep.bottomAnchor constant:8.0],
        [autoUpdateRow.leadingAnchor constraintEqualToAnchor:c1.leadingAnchor],
        [autoUpdateRow.trailingAnchor constraintEqualToAnchor:c1.trailingAnchor],
        [autoUpdateRow.bottomAnchor constraintEqualToAnchor:c1.bottomAnchor constant:-2.0],
    ]];

    // Card 2: Scrollable Release History + Build & Signing Note
    NSBox *historyCard = MSIMEMakeCardBox();
    NSView *c2 = historyCard.contentView;

    NSTextField *historyTitle = MSIMEMakeLabel(
        en ? @"Release History & Build Notes" : @"版本记录与架构信息",
        msime::mac::layout::kSectionFontSize, NSFontWeightSemibold, [NSColor labelColor]);
    NSTextField *repoLbl = MSIMEMakeLabel(vp[@"repo_slug"] ?: @"", 11.5, NSFontWeightRegular, [NSColor secondaryLabelColor]);

    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSZeroRect];
    scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    scrollView.drawsBackground = NO;
    scrollView.hasVerticalScroller = YES;

    FlippedDocumentView *docView = [[FlippedDocumentView alloc] initWithFrame:NSMakeRect(0, 0, 640, 220)];
    docView.translatesAutoresizingMaskIntoConstraints = NO;
    scrollView.documentView = docView;

    NSArray *entries = [vp[@"changelog"] isKindOfClass:[NSArray class]] ? vp[@"changelog"] : @[];
    NSView *prevEntry = nil;
    for (NSUInteger i = 0; i < entries.count; i++) {
        NSDictionary *entry = entries[i];
        NSView *row = [[NSView alloc] initWithFrame:NSZeroRect];
        row.translatesAutoresizingMaskIntoConstraints = NO;

        NSTextField *tagLbl = [NSTextField labelWithString:(entry[@"tag"] ?: @"")];
        tagLbl.translatesAutoresizingMaskIntoConstraints = NO;
        tagLbl.font = [NSFont monospacedSystemFontOfSize:12.0 weight:NSFontWeightSemibold];
        tagLbl.textColor = [NSColor labelColor];
        [tagLbl setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];
        [tagLbl setContentCompressionResistancePriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];

        NSTextField *entryTitle = MSIMEMakeLabel(entry[@"title"] ?: @"", 12.0, NSFontWeightMedium, [NSColor labelColor]);
        [entryTitle setContentHuggingPriority:NSLayoutPriorityDefaultHigh forOrientation:NSLayoutConstraintOrientationHorizontal];
        [entryTitle setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];

        NSTextField *dateLbl = MSIMEMakeLabel(entry[@"date"] ?: @"", 11.0, NSFontWeightRegular, [NSColor secondaryLabelColor]);
        [dateLbl setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];
        [dateLbl setContentCompressionResistancePriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationHorizontal];

        NSString *badge = [entry[@"status_badge"] isKindOfClass:[NSString class]] ? entry[@"status_badge"] : @"";
        BOOL isRemoteNew = [entry[@"is_remote_new"] boolValue];
        NSBox *pill = badge.length > 0 ? MSIMEMakeVersionPill(badge, isRemoteNew ? [NSColor systemOrangeColor] : accentColor) : nil;

        NSTextField *summaryLbl = [NSTextField wrappingLabelWithString:(entry[@"summary"] ?: @"")];
        summaryLbl.translatesAutoresizingMaskIntoConstraints = NO;
        summaryLbl.font = [NSFont systemFontOfSize:11.5 weight:NSFontWeightRegular];
        summaryLbl.textColor = [NSColor secondaryLabelColor];
        summaryLbl.preferredMaxLayoutWidth = 640.0;
        [summaryLbl setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
                                             forOrientation:NSLayoutConstraintOrientationHorizontal];

        [row addSubview:tagLbl];
        [row addSubview:entryTitle];
        if (pill) { [row addSubview:pill]; }
        [row addSubview:dateLbl];
        [row addSubview:summaryLbl];

        [NSLayoutConstraint activateConstraints:@[
            [tagLbl.topAnchor constraintEqualToAnchor:row.topAnchor],
            [tagLbl.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
            [entryTitle.leadingAnchor constraintEqualToAnchor:tagLbl.trailingAnchor constant:8.0],
            [entryTitle.firstBaselineAnchor constraintEqualToAnchor:tagLbl.firstBaselineAnchor],
            [dateLbl.trailingAnchor constraintEqualToAnchor:row.trailingAnchor constant:-6.0],
            [dateLbl.firstBaselineAnchor constraintEqualToAnchor:tagLbl.firstBaselineAnchor],
            [summaryLbl.topAnchor constraintEqualToAnchor:tagLbl.bottomAnchor constant:4.0],
            [summaryLbl.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
            [summaryLbl.trailingAnchor constraintEqualToAnchor:row.trailingAnchor constant:-6.0],
            [summaryLbl.bottomAnchor constraintEqualToAnchor:row.bottomAnchor constant:-6.0],
        ]];
        if (pill) {
            [NSLayoutConstraint activateConstraints:@[
                [pill.leadingAnchor constraintEqualToAnchor:entryTitle.trailingAnchor constant:8.0],
                [pill.centerYAnchor constraintEqualToAnchor:tagLbl.centerYAnchor],
                [pill.trailingAnchor constraintLessThanOrEqualToAnchor:dateLbl.leadingAnchor constant:-10.0],
            ]];
        } else {
            [entryTitle.trailingAnchor constraintLessThanOrEqualToAnchor:dateLbl.leadingAnchor constant:-10.0].active = YES;
        }

        [docView addSubview:row];
        [NSLayoutConstraint activateConstraints:@[
            [row.topAnchor constraintEqualToAnchor:(prevEntry ? prevEntry.bottomAnchor : docView.topAnchor)
                                         constant:(prevEntry ? 8.0 : 0.0)],
            [row.leadingAnchor constraintEqualToAnchor:docView.leadingAnchor],
            [row.trailingAnchor constraintEqualToAnchor:docView.trailingAnchor],
        ]];
        prevEntry = row;
    }
    if (prevEntry) {
        [prevEntry.bottomAnchor constraintEqualToAnchor:docView.bottomAnchor constant:-4.0].active = YES;
    }

    NSBox *archSep = [[NSBox alloc] initWithFrame:NSZeroRect];
    archSep.translatesAutoresizingMaskIntoConstraints = NO;
    archSep.boxType = NSBoxSeparator;

    NSString *archText = en
        ? [NSString stringWithFormat:@"Architecture: %@ · Signing: %@ · Build %@", vp[@"arch"] ?: @"", vp[@"signing_team"] ?: @"", vp[@"build"] ?: @""]
        : [NSString stringWithFormat:@"目标架构：%@ · 签名团队：%@ · 构建号 %@", vp[@"arch"] ?: @"", vp[@"signing_team"] ?: @"", vp[@"build"] ?: @""];
    NSTextField *archLbl = MSIMEMakeLabel(archText, 11.0, NSFontWeightRegular, [NSColor secondaryLabelColor]);

    [c2 addSubview:historyTitle];
    [c2 addSubview:repoLbl];
    [c2 addSubview:scrollView];
    [c2 addSubview:archSep];
    [c2 addSubview:archLbl];

    [NSLayoutConstraint activateConstraints:@[
        [historyTitle.topAnchor constraintEqualToAnchor:c2.topAnchor constant:2.0],
        [historyTitle.leadingAnchor constraintEqualToAnchor:c2.leadingAnchor],
        [repoLbl.trailingAnchor constraintEqualToAnchor:c2.trailingAnchor],
        [repoLbl.centerYAnchor constraintEqualToAnchor:historyTitle.centerYAnchor],
        [repoLbl.leadingAnchor constraintGreaterThanOrEqualToAnchor:historyTitle.trailingAnchor constant:12.0],

        [scrollView.topAnchor constraintEqualToAnchor:historyTitle.bottomAnchor constant:8.0],
        [scrollView.leadingAnchor constraintEqualToAnchor:c2.leadingAnchor],
        [scrollView.trailingAnchor constraintEqualToAnchor:c2.trailingAnchor],
        [scrollView.bottomAnchor constraintEqualToAnchor:archSep.topAnchor constant:-6.0],

        [docView.topAnchor constraintEqualToAnchor:scrollView.contentView.topAnchor],
        [docView.leadingAnchor constraintEqualToAnchor:scrollView.contentView.leadingAnchor],
        [docView.trailingAnchor constraintEqualToAnchor:scrollView.contentView.trailingAnchor],

        [archSep.leadingAnchor constraintEqualToAnchor:c2.leadingAnchor],
        [archSep.trailingAnchor constraintEqualToAnchor:c2.trailingAnchor],
        [archSep.bottomAnchor constraintEqualToAnchor:archLbl.topAnchor constant:-6.0],

        [archLbl.leadingAnchor constraintEqualToAnchor:c2.leadingAnchor],
        [archLbl.trailingAnchor constraintEqualToAnchor:c2.trailingAnchor],
        [archLbl.bottomAnchor constraintEqualToAnchor:c2.bottomAnchor constant:-2.0],
    ]];

    [container addSubview:statusCard];
    [container addSubview:historyCard];
    [NSLayoutConstraint activateConstraints:@[
        [statusCard.topAnchor constraintEqualToAnchor:container.topAnchor],
        [statusCard.leadingAnchor constraintEqualToAnchor:container.leadingAnchor],
        [statusCard.trailingAnchor constraintEqualToAnchor:container.trailingAnchor],

        [historyCard.topAnchor constraintEqualToAnchor:statusCard.bottomAnchor constant:msime::mac::layout::kCardSpacing],
        [historyCard.leadingAnchor constraintEqualToAnchor:container.leadingAnchor],
        [historyCard.trailingAnchor constraintEqualToAnchor:container.trailingAnchor],
        [historyCard.bottomAnchor constraintEqualToAnchor:container.bottomAnchor],
    ]];
    return container;
}
