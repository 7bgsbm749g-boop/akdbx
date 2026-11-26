"""The broker uses core X11 events and the X-Resource extension only."""
from Xlib import display, error
from Xlib.protocol import event


class TargetDisplay(display.Display):
    def list_extensions(self):
        # python-xlib registers extensions here during Display construction.
        # Its protocol tables are class attributes, but event numbers, errors
        # and major opcodes can differ between Xorg and XWayland connections.
        if 'extension_major_opcodes' not in vars(self.display):
            self.display.event_classes = event.event_class.copy()
            self.display.error_classes = error.xerror_class.copy()
            self.display.extension_major_opcodes = {}
        return [name for name in super().list_extensions() if name == 'X-Resource']
