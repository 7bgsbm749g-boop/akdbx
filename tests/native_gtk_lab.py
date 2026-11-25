"""Owned GTK test process. Invented values only; no real vault or desktop."""
import ctypes as C
import json
from pathlib import Path
import sys

gtk = C.CDLL('libgtk-3.so.0')
glib = C.CDLL('libglib-2.0.so.0')


def bind(lib, name, result, args):
    function = getattr(lib, name)
    function.restype, function.argtypes = result, args
    return function


init = bind(gtk, 'gtk_init', None, [C.c_void_p, C.c_void_p])
window_new = bind(gtk, 'gtk_window_new', C.c_void_p, [C.c_int])
box_new = bind(gtk, 'gtk_box_new', C.c_void_p, [C.c_int, C.c_int])
entry_new = bind(gtk, 'gtk_entry_new', C.c_void_p, [])
add = bind(gtk, 'gtk_container_add', None, [C.c_void_p, C.c_void_p])
pack = bind(gtk, 'gtk_box_pack_start', None, [C.c_void_p, C.c_void_p, C.c_int, C.c_int, C.c_uint])
visible = bind(gtk, 'gtk_entry_set_visibility', None, [C.c_void_p, C.c_int])
editable = bind(gtk, 'gtk_editable_set_editable', None, [C.c_void_p, C.c_int])
set_text = bind(gtk, 'gtk_entry_set_text', None, [C.c_void_p, C.c_char_p])
get_text = bind(gtk, 'gtk_entry_get_text', C.c_char_p, [C.c_void_p])
show = bind(gtk, 'gtk_widget_show_all', None, [C.c_void_p])
present = bind(gtk, 'gtk_window_present', None, [C.c_void_p])
focus = bind(gtk, 'gtk_widget_grab_focus', None, [C.c_void_p])
callback_type = C.CFUNCTYPE(C.c_int, C.c_void_p)
timeout = bind(glib, 'g_timeout_add', C.c_uint, [C.c_uint, callback_type, C.c_void_p])
main = bind(gtk, 'gtk_main', None, [])

directory = Path(sys.argv[1])
init(None, None)
window = window_new(0)
box = box_new(1, 8)
add(window, box)
entries = [entry_new() for _ in range(3)]
for entry in entries:
    pack(box, entry, 0, 0, 0)
visible(entries[1], 0)
editable(entries[2], 0)
set_text(entries[2], b'invented-capture-key')
show(window)
present(window)
focus(entries[1])


@callback_type
def tick(_):
    command = directory / 'command.json'
    if not command.exists():
        return 1
    data = json.loads(command.read_text())
    command.unlink()
    if 'focus' in data:
        focus(entries[data['focus']])
    if 'mask' in data:
        visible(entries[1], not data['mask'])
    # This is an isolated synthetic fixture: test assertions may inspect it.
    values = [get_text(entry).decode('utf-8') for entry in entries]
    (directory / 'result.json').write_text(json.dumps(values))
    return 1


timeout(40, tick, None)
gdk = C.CDLL('libgdk-3.so.0')
get_display = bind(gdk, 'gdk_display_get_default', C.c_void_p, [])
obj = C.CDLL('libgobject-2.0.so.0')
get_name = bind(obj, 'g_type_name_from_instance', C.c_char_p, [C.c_void_p])
(directory / 'ready').write_text(get_name(get_display()).decode())
main()
