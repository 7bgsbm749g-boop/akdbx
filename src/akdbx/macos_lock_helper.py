"""Listen on Cocoa's main run loop in the user's login session."""
import os
import sys
import threading


def main():
    import objc
    from AppKit import NSWorkspace, NSWorkspaceWillSleepNotification, NSWorkspaceDidWakeNotification
    from Foundation import NSDistributedNotificationCenter, NSNotificationSuspensionBehaviorDeliverImmediately, NSObject, NSRunLoop

    # The pipe also closes on an abrupt broker exit.
    def parent_closed():
        sys.stdin.buffer.read(1)
        os._exit(0)

    threading.Thread(target=parent_closed, daemon=True).start()
    distributed = NSDistributedNotificationCenter.defaultCenter()
    workspace = NSWorkspace.sharedWorkspace().notificationCenter()
    class LockObserver(NSObject):
        @objc.typedSelector(b'v@:@')
        def lock_(self, notification):
            os.write(1, b'L')

    observer = LockObserver.alloc().init()
    distributed.addObserver_selector_name_object_suspensionBehavior_(
        observer, 'lock:', 'com.apple.screenIsLocked', None, NSNotificationSuspensionBehaviorDeliverImmediately)
    for name in (NSWorkspaceWillSleepNotification, NSWorkspaceDidWakeNotification):
        workspace.addObserver_selector_name_object_(observer, 'lock:', name, None)
    os.write(1, b'R')
    NSRunLoop.currentRunLoop().run()


if __name__ == '__main__':
    main()
