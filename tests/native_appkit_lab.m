// A separate, foreground AppKit process. Only synthetic test data is used.
#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>

int main(int argc, const char **argv) {
    @autoreleasepool {
        NSString *directory = @(argv[1]);
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(200, 200, 450, 380)
            styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
        NSTextField *plain = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 320, 350, 32)];
        NSSecureTextField *stock = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(20, 215, 350, 32)];
        NSTextView *read = [[NSTextView alloc] initWithFrame:NSMakeRect(20, 145, 350, 44)];
        read.string = @"invented-read-🐈";
        read.editable = NO;
        read.selectable = YES;
        NSArray *fields = @[plain, stock, read];
        for (NSView *field in fields) [window.contentView addSubview:field];
        [window makeKeyAndOrderFront:nil];
        [app activateIgnoringOtherApps:YES];
        [window makeFirstResponder:plain];
        NSString *command = [directory stringByAppendingPathComponent:@"command"];
        NSString *result = [directory stringByAppendingPathComponent:@"result"];
        [NSTimer scheduledTimerWithTimeInterval:0.02 repeats:YES block:^(NSTimer *timer) {
            NSString *cmd = [NSString stringWithContentsOfFile:command encoding:NSUTF8StringEncoding error:NULL];
            if (!cmd) return;
            [[NSFileManager defaultManager] removeItemAtPath:command error:NULL];
            if ([cmd hasPrefix:@"focus"]) [window makeFirstResponder:fields[[[cmd substringFromIndex:5] integerValue]]];
            if ([cmd isEqual:@"replace"]) {
                [plain removeFromSuperview];
                NSTextField *other = [[NSTextField alloc] initWithFrame:plain.frame];
                [window.contentView addSubview:other];
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
