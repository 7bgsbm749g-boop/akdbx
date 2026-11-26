// A separate, foreground AppKit process. Only synthetic test data is used.
#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>

// An app that caps a field's length while it is edited.
@interface Truncate : NSObject <NSTextFieldDelegate>
@end
@implementation Truncate
- (void)controlTextDidChange:(NSNotification *)note {
    NSText *editor = [note.object currentEditor];
    if (editor.string.length > 8) editor.string = [editor.string substringToIndex:8];
}
@end

// A formatter that rejects an edit longer than 8 UTF-16 units.
@interface Reject : NSFormatter
@end
@implementation Reject
- (NSString *)stringForObjectValue:(id)value { return [value isKindOfClass:NSString.class] ? value : @""; }
- (BOOL)getObjectValue:(id *)value forString:(NSString *)string errorDescription:(NSString **)error {
    *value = string;
    return YES;
}
- (BOOL)isPartialStringValid:(NSString *)partial newEditingString:(NSString **)replacement
            errorDescription:(NSString **)error {
    return partial.length <= 8;
}
@end

int main(int argc, const char **argv) {
    @autoreleasepool {
        NSString *directory = @(argv[1]);
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(200, 200, 450, 380)
            styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
        // A native accessibility group holds the plain field. The web-view
        // check must pass ordinary groups.
        NSView *group = [[NSView alloc] initWithFrame:NSMakeRect(10, 310, 370, 52)];
        group.accessibilityElement = YES;
        group.accessibilityRole = NSAccessibilityGroupRole;
        NSTextField *plain = [[NSTextField alloc] initWithFrame:NSMakeRect(10, 10, 350, 32)];
        [group addSubview:plain];
        NSSecureTextField *stock = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(20, 215, 350, 32)];
        NSTextView *read = [[NSTextView alloc] initWithFrame:NSMakeRect(20, 145, 350, 44)];
        read.string = @"invented-read-🐈";
        read.editable = NO;
        read.selectable = YES;
        NSTextField *other = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 95, 350, 32)];
        [other setAccessibilityRole:NSAccessibilityTextFieldRole];
        other.editable = NO;
        other.selectable = YES;
        other.stringValue = @"read-only sibling";
        NSArray *fields = @[plain, stock, read, other];
        for (NSView *view in @[group, stock, read, other]) [window.contentView addSubview:view];
        [window makeKeyAndOrderFront:nil];
        [app activateIgnoringOtherApps:YES];
        [window makeFirstResponder:plain];
        Truncate *limiter = [Truncate new];
        NSString *command = [directory stringByAppendingPathComponent:@"command"];
        NSString *result = [directory stringByAppendingPathComponent:@"result"];
        [NSTimer scheduledTimerWithTimeInterval:0.02 repeats:YES block:^(NSTimer *timer) {
            NSString *cmd = [NSString stringWithContentsOfFile:command encoding:NSUTF8StringEncoding error:NULL];
            if (!cmd) return;
            [[NSFileManager defaultManager] removeItemAtPath:command error:NULL];
            if ([cmd hasPrefix:@"focus"]) [window makeFirstResponder:fields[[[cmd substringFromIndex:5] integerValue]]];
            if ([cmd isEqual:@"truncate"]) stock.delegate = limiter;
            if ([cmd isEqual:@"reject"]) stock.formatter = [Reject new];
            if ([cmd isEqual:@"no-bullets"]) ((NSSecureTextFieldCell *)stock.cell).echosBullets = NO;
            if ([cmd isEqual:@"prefill"]) stock.stringValue = @"prefilled";
            if ([cmd isEqual:@"partly-offscreen"]) {
                // The read-only view falls below the display. The focused
                // upper text field stays on screen.
                [window setFrameOrigin:NSMakePoint(NSMinX(window.frame), NSMinY(window.screen.frame) - 200)];
            }
            if ([cmd isEqual:@"replace"]) {
                [plain removeFromSuperview];
                NSTextField *other = [[NSTextField alloc] initWithFrame:plain.frame];
                [group addSubview:other];
                [window makeFirstResponder:other];
            }
            if ([cmd isEqual:@"web"]) {
                WKWebView *web = [[WKWebView alloc] initWithFrame:NSMakeRect(20, 45, 340, 80)];
                [window.contentView addSubview:web];
                [web loadHTMLString:@"<input value='fixture'>" baseURL:nil];
            }
            NSMutableArray *values = [NSMutableArray new];
            for (NSTextField *field in @[plain, stock]) {
                [values addObject:field.currentEditor ? field.currentEditor.string : field.stringValue];
            }
            [[NSJSONSerialization dataWithJSONObject:values options:0 error:NULL] writeToFile:result atomically:YES];
        }];
        [app run];
    }
}
