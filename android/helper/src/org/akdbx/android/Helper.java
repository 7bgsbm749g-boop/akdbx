package org.akdbx.android;

import android.app.UiAutomation;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.HandlerThread;
import android.os.Looper;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import android.accessibilityservice.AccessibilityServiceInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * akdbx Android helper. The broker runs it with app_process as the adb shell
 * user and sends one JSON request on stdin. It answers with one line that
 * starts with RESULT_PREFIX. Values to fill arrive only on stdin and never
 * appear in the answer, an exception message, a log or an argument.
 */
public final class Helper {
    static final int PROTOCOL = 1;
    static final String RESULT_PREFIX = "AKDBX-ANDROID-RESULT ";
    static final String NEED_PREFIX = "AKDBX-ANDROID-NEED ";
    static final int MAX_REQUEST = 256 * 1024;
    static final int MAX_FIELDS = 64;
    static final int MAX_NODES = 6000;
    static final String WEBVIEW_CLASS = "android.webkit.WebView";
    static final String SETTINGS_SPEAK_PASSWORD = "speak_password";

    private static PrintStream out;

    public static void main(String[] args) {
        out = System.out;
        // Nothing else may write to the answer stream.
        System.setOut(System.err);
        JSONObject answer;
        String op = "";
        try {
            JSONObject request = new JSONObject(readRequest());
            op = request.optString("op", "");
            answer = new Helper().run(op, request);
        } catch (Refusal refusal) {
            answer = failure(refusal.reason);
        } catch (Throwable error) {
            // Never print the message: it can hold request text.
            answer = failure("helper failed: " + error.getClass().getSimpleName());
        }
        try {
            answer.put("protocol", PROTOCOL);
        } catch (Exception ignored) {
        }
        out.println(RESULT_PREFIX + answer.toString());
        out.flush();
        System.exit(0);
    }

    static final class Refusal extends Exception {
        final String reason;

        Refusal(String reason) {
            super(null, null, false, false);
            this.reason = reason;
        }
    }

    static JSONObject failure(String reason) {
        JSONObject answer = new JSONObject();
        try {
            answer.put("ok", false);
            answer.put("error", reason);
        } catch (Exception ignored) {
        }
        return answer;
    }

    private static BufferedReader input;

    /** One line from stdin: the request, then any answer the broker sends to a NEED line. */
    static String readRequest() throws Exception {
        if (input == null) {
            input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8), 8192);
        }
        BufferedReader reader = input;
        StringBuilder text = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1) {
            if (c == '\n') {
                break;
            }
            text.append((char) c);
            if (text.length() > MAX_REQUEST) {
                throw new Refusal("request too large");
            }
        }
        return text.toString();
    }

    private UiAutomation automation;
    private HandlerThread thread;

    JSONObject run(String op, JSONObject request) throws Exception {
        if ("probe".equals(op)) {
            return probe();
        }
        if (!"inspect".equals(op) && !"check".equals(op) && !"fill".equals(op) && !"context".equals(op)
                && !"google_sign_in".equals(op) && !"type".equals(op)) {
            throw new Refusal("unknown helper operation");
        }
        connect();
        try {
            if ("inspect".equals(op)) {
                return inspect(request);
            }
            if ("check".equals(op)) {
                return check(request);
            }
            if ("context".equals(op)) {
                Scene scene = scene();
                JSONObject answer = new JSONObject();
                answer.put("ok", true);
                answer.put("context", context(scene, walk(scene.root)));
                return answer;
            }
            if ("type".equals(op)) {
                return type(request);
            }
            if ("google_sign_in".equals(op)) {
                return googleSignIn(request);
            }
            return fill(request);
        } finally {
            disconnect();
        }
    }

    // ----- device facts -------------------------------------------------

    static String bootId() throws Exception {
        try (FileInputStream in = new FileInputStream("/proc/sys/kernel/random/boot_id")) {
            byte[] data = new byte[64];
            int n = in.read(data);
            return new String(data, 0, Math.max(n, 0), StandardCharsets.US_ASCII).trim();
        }
    }

    static String setting(String namespace, String key) {
        try {
            Process process = new ProcessBuilder("/system/bin/cmd", "settings", "get", namespace, key)
                    .redirectErrorStream(true).start();
            process.getOutputStream().close();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            String line = reader.readLine();
            process.waitFor();
            return line == null ? "" : line.trim();
        } catch (Exception error) {
            return "";
        }
    }

    /** True unless the device is known to keep password text from accessibility. */
    static boolean speaksPasswords() {
        String value = setting("secure", SETTINGS_SPEAK_PASSWORD);
        if (value.isEmpty() || "null".equals(value)) {
            return false; // Unset: the platform default is 0.
        }
        try {
            return Integer.parseInt(value) != 0;
        } catch (NumberFormatException unknown) {
            return true;
        }
    }

    JSONObject probe() throws Exception {
        JSONObject answer = new JSONObject();
        answer.put("ok", true);
        answer.put("boot_id", bootId());
        answer.put("sdk", android.os.Build.VERSION.SDK_INT);
        answer.put("speak_password", speaksPasswords());
        return answer;
    }

    /** The focused task as the system reports it. */
    static final class Task {
        ComponentName activity;
        int taskId;
        int userId;
        String label;
    }

    static Task focusedTask() {
        try {
            Object service = Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
            Object info = service.getClass().getMethod("getFocusedRootTaskInfo").invoke(service);
            if (info != null) {
                Object top = info.getClass().getField("topActivity").get(info);
                if (top instanceof ComponentName) {
                    Task task = new Task();
                    task.activity = (ComponentName) top;
                    task.taskId = info.getClass().getField("taskId").getInt(info);
                    task.userId = info.getClass().getField("userId").getInt(info);
                    Object description = info.getClass().getField("taskDescription").get(info);
                    if (description instanceof android.app.ActivityManager.TaskDescription) {
                        task.label = ((android.app.ActivityManager.TaskDescription) description).getLabel();
                    }
                    return task;
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    static ComponentName focusedActivity() {
        Task task = focusedTask();
        if (task != null) {
            return task.activity;
        }
        return null;
    }

    static final class App {
        String packageName;
        List<String> signers = new ArrayList<>();
        List<String> lineage = new ArrayList<>();
        boolean debuggable;
        boolean system;
        int uid;
    }

    static App app(String packageName, int userId) throws Exception {
        Object pm = Class.forName("android.app.ActivityThread").getMethod("getPackageManager").invoke(null);
        PackageInfo info = null;
        int flags = PackageManager.GET_SIGNING_CERTIFICATES;
        try {
            Method method = pm.getClass().getMethod("getPackageInfo", String.class, long.class, int.class);
            info = (PackageInfo) method.invoke(pm, packageName, (long) flags, userId);
        } catch (NoSuchMethodException missing) {
            Method method = pm.getClass().getMethod("getPackageInfo", String.class, int.class, int.class);
            info = (PackageInfo) method.invoke(pm, packageName, flags, userId);
        }
        if (info == null || info.applicationInfo == null) {
            throw new Refusal("target app is not installed");
        }
        App app = new App();
        app.packageName = packageName;
        app.uid = info.applicationInfo.uid;
        app.debuggable = (info.applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        app.system = (info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
        SigningInfo signing = info.signingInfo;
        if (signing == null || signing.hasMultipleSigners()) {
            // Several current signers: refuse rather than choose one.
            throw new Refusal("target app has no single signing certificate");
        }
        Signature[] history = signing.getSigningCertificateHistory();
        if (history == null || history.length == 0) {
            throw new Refusal("target app has no signing certificate");
        }
        // The current signer is the last entry of the rotation history.
        app.signers.add(sha256(history[history.length - 1].toByteArray()));
        for (Signature past : history) {
            app.lineage.add(sha256(past.toByteArray()));
        }
        return app;
    }

    static String sha256(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder text = new StringBuilder();
        for (byte b : digest) {
            text.append(String.format("%02X", b & 0xff));
        }
        return text.toString();
    }

    // ----- UiAutomation ---------------------------------------------------

    void connect() throws Exception {
        // Accessibility clients need a main looper; this process has none yet.
        if (Looper.getMainLooper() == null) {
            Looper.prepareMainLooper();
        }
        thread = new HandlerThread("akdbx-android");
        thread.start();
        Looper looper = thread.getLooper();
        Class<?> connectionClass = Class.forName("android.app.UiAutomationConnection");
        Object connection = connectionClass.getDeclaredConstructor().newInstance();
        Class<?> connectionInterface = Class.forName("android.app.IUiAutomationConnection");
        UiAutomation created = null;
        try {
            Constructor<UiAutomation> constructor = UiAutomation.class.getDeclaredConstructor(Looper.class, connectionInterface);
            constructor.setAccessible(true);
            created = constructor.newInstance(looper, connection);
        } catch (NoSuchMethodException missing) {
            Constructor<UiAutomation> constructor = UiAutomation.class.getDeclaredConstructor(Context.class, connectionInterface);
            constructor.setAccessible(true);
            created = constructor.newInstance(new LooperContext(looper), connection);
        }
        automation = created;
        Method connect = UiAutomation.class.getDeclaredMethod("connect");
        connect.setAccessible(true);
        connect.invoke(automation);
        AccessibilityServiceInfo info = automation.getServiceInfo();
        info.flags |= AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
                | AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
                | AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS;
        automation.setServiceInfo(info);
        try {
            automation.waitForIdle(200, 3000);
        } catch (Exception ignored) {
        }
    }

    void disconnect() {
        try {
            if (automation != null) {
                Method disconnect = UiAutomation.class.getDeclaredMethod("disconnect");
                disconnect.setAccessible(true);
                disconnect.invoke(automation);
            }
        } catch (Throwable ignored) {
        }
        if (thread != null) {
            thread.quitSafely();
        }
    }

    static final class LooperContext extends ContextWrapper {
        private final Looper looper;

        LooperContext(Looper looper) {
            super(null);
            this.looper = looper;
        }

        @Override
        public Looper getMainLooper() {
            return looper;
        }

        // Context.getDisplayId() is hidden in the SDK; this overrides it at run time.
        public int getDisplayId() {
            return 0;
        }

        @Override
        public String getPackageName() {
            return "com.android.shell";
        }

        @Override
        public String getOpPackageName() {
            return "com.android.shell";
        }
    }

    // ----- windows and nodes ----------------------------------------------

    /** The focused, active application window and its system-reported focused activity. */
    static final class Scene {
        AccessibilityWindowInfo window;
        AccessibilityNodeInfo root;
        ComponentName activity;
        Task task;
        App app;
    }

    Scene scene() throws Exception {
        Task task = focusedTask();
        if (task == null) {
            throw new Refusal("no focused activity");
        }
        ComponentName activity = task.activity;
        AccessibilityWindowInfo chosen = null;
        for (int attempt = 0; attempt < 10 && chosen == null; attempt++) {
            for (AccessibilityWindowInfo window : automation.getWindows()) {
                if (window.getType() == AccessibilityWindowInfo.TYPE_APPLICATION && window.isFocused() && window.isActive()) {
                    chosen = window;
                }
            }
            if (chosen == null) {
                Thread.sleep(150);
            }
        }
        if (chosen == null) {
            throw new Refusal("no focused application window");
        }
        AccessibilityNodeInfo root = chosen.getRoot();
        if (root == null || root.getPackageName() == null) {
            throw new Refusal("focused window has no content");
        }
        // The app reports its own package name in each node; the system reports
        // the focused activity. A mismatch means the window is not that activity's.
        if (!activity.getPackageName().contentEquals(root.getPackageName())) {
            throw new Refusal("focused window does not belong to the focused activity");
        }
        Scene scene = new Scene();
        scene.window = chosen;
        scene.root = root;
        scene.activity = activity;
        scene.task = task;
        // A work profile's app exists only for that profile's Android user.
        scene.app = app(activity.getPackageName(), task.userId);
        return scene;
    }

    static long sourceNodeId(AccessibilityNodeInfo node) throws Exception {
        Method method = AccessibilityNodeInfo.class.getDeclaredMethod("getSourceNodeId");
        method.setAccessible(true);
        return (Long) method.invoke(node);
    }

    static final class Walk {
        final List<AccessibilityNodeInfo> nodes = new ArrayList<>();
        boolean webWithoutContent;
    }

    static Walk walk(AccessibilityNodeInfo root) {
        Walk walk = new Walk();
        ArrayDeque<AccessibilityNodeInfo> queue = new ArrayDeque<>();
        queue.add(root);
        while (!queue.isEmpty() && walk.nodes.size() < MAX_NODES) {
            AccessibilityNodeInfo node = queue.removeFirst();
            walk.nodes.add(node);
            if (WEBVIEW_CLASS.contentEquals(String.valueOf(node.getClassName())) && node.getChildCount() == 0) {
                walk.webWithoutContent = true;
            }
            for (int i = 0; i < node.getChildCount(); i++) {
                AccessibilityNodeInfo child = node.getChild(i);
                if (child != null) {
                    queue.add(child);
                }
            }
        }
        return walk;
    }

    /**
     * True when an app's WebView shows no content in the tree yet. Chrome's
     * own pages are not read here: the broker reads them through Chrome's
     * DevTools socket, because Chrome's accessibility tree can be stale.
     */
    static boolean webPending(Scene scene, Walk walk) {
        return walk.webWithoutContent && !isChrome(scene.app.packageName);
    }

    Walk settledWalk(Scene scene) throws Exception {
        Walk walk = walk(scene.root);
        // Chromium builds web content for accessibility only after a client
        // connects; wait briefly for it.
        for (int attempt = 0; attempt < 8 && webPending(scene, walk); attempt++) {
            Thread.sleep(200);
            scene.root.refresh();
            walk = walk(scene.root);
        }
        return walk;
    }

    static final String PANEL_ACTIVITY = "com.android.settings/.panel.SettingsPanelActivity";

    static boolean waitFor(String activity, long millis) throws Exception {
        long end = System.currentTimeMillis() + millis;
        while (System.currentTimeMillis() < end) {
            ComponentName now = focusedActivity();
            if (now != null && activity.equals(now.flattenToShortString())) {
                return true;
            }
            Thread.sleep(100);
        }
        return false;
    }

    static int run(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        process.getOutputStream().close();
        byte[] sink = new byte[4096];
        while (process.getInputStream().read(sink) != -1) {
            // Discard: nothing from these commands is needed.
        }
        return process.waitFor();
    }

    /**
     * Chromium can stop giving a WebView's page to accessibility and turns it
     * on again only when its activity resumes. Pause the activity with a
     * system panel on top, close the panel with Back, and check that the same
     * activity is focused again. Back is sent only while the panel is focused.
     */
    Scene wake(Scene scene) throws Exception {
        String original = scene.activity.flattenToShortString();
        run("/system/bin/am", "start", "-a", "android.settings.panel.action.VOLUME");
        if (!waitFor(PANEL_ACTIVITY, 3000)) {
            throw new Refusal("could not wake the page's accessibility tree; reload the page");
        }
        run("/system/bin/input", "keyevent", "KEYCODE_BACK");
        if (!waitFor(original, 3000)) {
            throw new Refusal("could not return to the app after waking its accessibility tree");
        }
        Scene again = null;
        for (int attempt = 0; attempt < 15; attempt++) {
            Thread.sleep(200);
            try {
                again = scene();
            } catch (Refusal notYet) {
                continue;
            }
            Walk walk = walk(again.root);
            if (!webPending(again, walk)) {
                return again;
            }
        }
        return again == null ? scene() : again;
    }

    /** The scene and its settled walk; wakes Chrome's tree when allowed. */
    Object[] look(boolean allowWake) throws Exception {
        Scene scene = scene();
        Walk walk = settledWalk(scene);
        if (allowWake && webPending(scene, walk)) {
            scene = wake(scene);
            walk = settledWalk(scene);
            // The page's tree arrives in parts after a wake: wait until it stops growing.
            for (int attempt = 0; attempt < 15; attempt++) {
                Thread.sleep(200);
                scene.root.refresh();
                Walk next = walk(scene.root);
                boolean stable = next.nodes.size() == walk.nodes.size();
                walk = next;
                if (stable && !webPending(scene, walk)) {
                    break;
                }
            }
        }
        return new Object[] {scene, walk};
    }

    static String chromeRole(AccessibilityNodeInfo node) {
        Bundle extras = node.getExtras();
        return extras == null ? null : extras.getString("AccessibilityNodeInfo.chromeRole");
    }

    /** True when an ancestor is an inline frame: the field is in a child document. */
    static boolean inFrame(AccessibilityNodeInfo node) {
        AccessibilityNodeInfo current = node.getParent();
        int depth = 0;
        while (current != null && depth < 256) {
            String role = chromeRole(current);
            if (role != null && role.toLowerCase(java.util.Locale.ROOT).contains("iframe")) {
                return true;
            }
            if (WEBVIEW_CLASS.contentEquals(String.valueOf(current.getClassName()))) {
                return false;
            }
            current = current.getParent();
            depth++;
        }
        return false;
    }

    static boolean inWeb(AccessibilityNodeInfo node) {
        AccessibilityNodeInfo current = node;
        int depth = 0;
        while (current != null && depth < 256) {
            if (WEBVIEW_CLASS.contentEquals(String.valueOf(current.getClassName())) || chromeRole(current) != null) {
                return true;
            }
            current = current.getParent();
            depth++;
        }
        return false;
    }

    static boolean isField(AccessibilityNodeInfo node) {
        return node.isEditable() || node.isPassword();
    }

    JSONObject describe(AccessibilityNodeInfo node) throws Exception {
        JSONObject field = new JSONObject();
        field.put("window_id", node.getWindowId());
        field.put("node_id", Long.toString(sourceNodeId(node)));
        field.put("class", String.valueOf(node.getClassName()));
        field.put("view_id", node.getViewIdResourceName() == null ? JSONObject.NULL : node.getViewIdResourceName());
        field.put("package", String.valueOf(node.getPackageName()));
        CharSequence hint = node.getHintText();
        field.put("hint", hint == null ? JSONObject.NULL : clip(hint.toString()));
        CharSequence label = node.getContentDescription();
        field.put("label", label == null ? JSONObject.NULL : clip(label.toString()));
        AccessibilityNodeInfo labeledBy = node.getLabeledBy();
        if (labeledBy != null && labeledBy.getText() != null && !labeledBy.isPassword()) {
            field.put("labeled_by", clip(labeledBy.getText().toString()));
        }
        field.put("password", node.isPassword());
        field.put("editable", node.isEditable());
        field.put("enabled", node.isEnabled());
        field.put("visible", node.isVisibleToUser());
        field.put("focused", node.isFocused());
        field.put("has_text", node.getText() != null && node.getText().length() > 0
                && (node.getHintText() == null || !node.getHintText().toString().contentEquals(node.getText())));
        field.put("input_type", node.getInputType());
        Rect bounds = new Rect();
        node.getBoundsInScreen(bounds);
        field.put("bounds", new JSONArray().put(bounds.left).put(bounds.top).put(bounds.right).put(bounds.bottom));
        boolean web = inWeb(node);
        field.put("web", web);
        if (web) {
            field.put("in_frame", inFrame(node));
        }
        return field;
    }

    /** The Chrome build whose address bar the broker matches with Chrome's tab list. */
    static boolean isChrome(String packageName) {
        return "com.android.chrome".equals(packageName);
    }

    static String clip(String text) {
        return text.length() > 200 ? text.substring(0, 200) : text;
    }

    // ----- Chrome page origin ---------------------------------------------

    static final String CHROME_URL_BAR = ":id/url_bar";
    static final String WIDGET_EDIT_TEXT = "android.widget.EditText";
    static final String WIDGET_TEXT_VIEW = "android.widget.TextView";

    /** The host and port that Chrome's own address bar shows, or null. */
    static String addressBarAuthority(Scene scene, Walk walk) {
        String found = null;
        for (AccessibilityNodeInfo node : walk.nodes) {
            String id = node.getViewIdResourceName();
            // A web page's element can carry the same id (Chromium reports HTML
            // ids as view ids): only Chrome's own native view counts.
            if (id != null && id.equals(scene.app.packageName + CHROME_URL_BAR) && !inWeb(node)
                    && (WIDGET_EDIT_TEXT.contentEquals(String.valueOf(node.getClassName()))
                        || WIDGET_TEXT_VIEW.contentEquals(String.valueOf(node.getClassName())))) {
                if (found != null || node.isFocused() || node.getText() == null) {
                    return null; // Two bars, or the user is editing it.
                }
                String text = node.getText().toString().trim();
                int scheme = text.indexOf("://");
                if (scheme >= 0) {
                    text = text.substring(scheme + 3);
                }
                int end = text.length();
                for (char stop : new char[] {'/', '?', '#'}) {
                    int at = text.indexOf(stop);
                    if (at >= 0 && at < end) {
                        end = at;
                    }
                }
                found = text.substring(0, end).toLowerCase(java.util.Locale.ROOT);
                if (found.isEmpty() || found.contains(" ") || found.contains("@")) {
                    return null;
                }
            }
        }
        return found;
    }

    // ----- typing into Chrome ---------------------------------------------

    static final String[] CHROME_ACTIVITIES = {
        "com.android.chrome/org.chromium.chrome.browser.ChromeTabbedActivity",
        "com.android.chrome/org.chromium.chrome.browser.customtabs.CustomTabActivity",
    };

    /** Key events for each character, or null when one has no key on the virtual keyboard. */
    static android.view.KeyEvent[] keyEvents(String value) {
        android.view.KeyCharacterMap map = android.view.KeyCharacterMap.load(android.view.KeyCharacterMap.VIRTUAL_KEYBOARD);
        List<android.view.KeyEvent> events = new ArrayList<>();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                return null;
            }
            android.view.KeyEvent[] keys = map.getEvents(new char[] {c});
            if (keys == null || keys.length == 0) {
                return null;
            }
            for (android.view.KeyEvent key : keys) {
                events.add(key);
            }
        }
        return events.toArray(new android.view.KeyEvent[0]);
    }

    /** Inject one event that the system delivers only to a window of targetUid. */
    static boolean inject(android.view.InputEvent event, int targetUid) throws Exception {
        Object manager;
        try {
            manager = Class.forName("android.hardware.input.InputManagerGlobal").getMethod("getInstance").invoke(null);
        } catch (ClassNotFoundException old) {
            manager = Class.forName("android.hardware.input.InputManager").getMethod("getInstance").invoke(null);
        }
        Method method;
        try {
            method = manager.getClass().getMethod("injectInputEvent", android.view.InputEvent.class, int.class, int.class);
        } catch (NoSuchMethodException old) {
            method = manager.getClass().getMethod("injectInputEventToTarget", android.view.InputEvent.class, int.class, int.class);
        }
        // Mode 2: wait until the target window handled it.
        return (Boolean) method.invoke(manager, event, 2, targetUid);
    }

    /**
     * Type a value (the broker's random, non-secret check string) as key
     * events into Chrome's focused field. The system delivers each event only
     * to a window owned by Chrome's Android user id, after this run checks
     * that Chrome's tab or Custom Tab is focused in the pinned task and its
     * own address bar shows the pinned host. Only real Chrome can then report
     * the string in the pinned element over DevTools.
     */
    JSONObject type(JSONObject request) throws Exception {
        if (!bootId().equals(request.getString("boot_id"))) {
            throw new Refusal("device restarted since the pin");
        }
        String value = request.getString("value");
        android.view.KeyEvent[] events = keyEvents(value);
        if (events == null) {
            throw new Refusal("value has a character with no key; only printable ASCII is typed");
        }
        if (speaksPasswords()) {
            throw new Refusal("device lets accessibility read password text (speak_password is not 0)");
        }
        Scene scene = scene();
        String activity = scene.activity.flattenToShortString();
        if (!isChrome(scene.app.packageName) || scene.app.lineage.isEmpty() || !GOOGLE_SIGNER.equals(scene.app.lineage.get(0))
                || scene.app.debuggable || !(CHROME_ACTIVITIES[0].equals(activity) || CHROME_ACTIVITIES[1].equals(activity))
                || scene.task.taskId != request.getInt("task_id")) {
            throw new Refusal("Chrome is not the focused app in the pinned task");
        }
        String authority = addressBarAuthority(scene, walk(scene.root));
        if (authority == null || !authority.equals(request.getString("address_bar"))) {
            throw new Refusal("Chrome's address bar does not show the pinned site");
        }
        int typed = 0;
        for (android.view.KeyEvent event : events) {
            android.view.KeyEvent now = android.view.KeyEvent.changeTimeRepeat(event, android.os.SystemClock.uptimeMillis(), 0);
            if (!inject(now, scene.app.uid)) {
                JSONObject answer = new JSONObject();
                answer.put("ok", true);
                answer.put("complete", false);
                answer.put("started", typed > 0);
                return answer;
            }
            typed++;
        }
        JSONObject answer = new JSONObject();
        answer.put("ok", true);
        answer.put("complete", true);
        answer.put("started", true);
        return answer;
    }

    // ----- Google account sign-in in one run ------------------------------

    static final String GMS_SIGN_IN = "com.google.android.gms/.auth.uiflows.minutemaid.MinuteMaidActivity";
    static final String GOOGLE_SIGNER = "F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83";

    /** The one visible, enabled web field of the kind asked for, or null. */
    static AccessibilityNodeInfo signInField(Walk walk, String kind) {
        AccessibilityNodeInfo found = null;
        for (AccessibilityNodeInfo node : walk.nodes) {
            if (!isField(node) || !node.isEnabled() || !node.isVisibleToUser() || !inWeb(node) || inFrame(node)) {
                continue;
            }
            String id = node.getViewIdResourceName();
            boolean match = "email".equals(kind) ? !node.isPassword() && "identifierId".equals(id)
                    : "password".equals(kind) ? node.isPassword()
                    // Google's authenticator-app challenge; other challenges (SMS, recovery) stop the run.
                    : !node.isPassword() && "totpPin".equals(id);
            if (match) {
                if (found != null) {
                    return null; // Two candidates: not a page this run knows.
                }
                found = node;
            }
        }
        return found;
    }

    static boolean hasWebField(Walk walk) {
        for (AccessibilityNodeInfo node : walk.nodes) {
            if (isField(node) && node.isVisibleToUser() && inWeb(node)) {
                return true;
            }
        }
        return false;
    }

    static final String LEFT_SIGN_IN = "Google sign-in screen changed";

    /**
     * The sign-in scene, refused unless it is Google's signed sign-in
     * activity in the run's own task; null while a page is still loading.
     */
    Scene signInScene(int taskId) throws Exception {
        Task task = focusedTask();
        if (task == null || !GMS_SIGN_IN.equals(task.activity.flattenToShortString()) || task.taskId != taskId) {
            throw new Refusal(LEFT_SIGN_IN);
        }
        Scene scene;
        try {
            scene = scene();
        } catch (Refusal loading) {
            return null; // No focused window or no content yet.
        }
        if (!GMS_SIGN_IN.equals(scene.activity.flattenToShortString()) || scene.app.debuggable
                || scene.app.lineage.isEmpty() || !GOOGLE_SIGNER.equals(scene.app.lineage.get(0))
                || scene.task.taskId != taskId) {
            throw new Refusal(LEFT_SIGN_IN);
        }
        return scene;
    }

    /** Wait until the field of this kind shows and the previous field is gone. */
    AccessibilityNodeInfo await(int taskId, String kind, long previous, long millis) throws Exception {
        long end = System.currentTimeMillis() + millis;
        while (System.currentTimeMillis() < end) {
            Scene scene = signInScene(taskId);
            if (scene == null) {
                Thread.sleep(250);
                continue;
            }
            Walk walk = walk(scene.root);
            boolean previousGone = true;
            if (previous != Long.MIN_VALUE) {
                for (AccessibilityNodeInfo node : walk.nodes) {
                    if (sourceNodeId(node) == previous && node.isVisibleToUser()) {
                        previousGone = false;
                    }
                }
            }
            AccessibilityNodeInfo field = previousGone ? signInField(walk, kind) : null;
            if (field != null) {
                return field;
            }
            Thread.sleep(250);
        }
        return null;
    }

    /**
     * Set a field to a value and confirm it holds it. The field is emptied and
     * checked first, so an unchanged masked value of the same length never
     * counts as the new one.
     */
    static boolean setAndConfirm(AccessibilityNodeInfo node, String value) throws Exception {
        node.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
        for (String step : new String[] {"", value}) {
            Bundle arguments = new Bundle();
            arguments.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, step);
            if (!node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments)) {
                return false;
            }
            boolean holds = false;
            for (int attempt = 0; attempt < 10 && !holds; attempt++) {
                if (!node.refresh()) {
                    return false;
                }
                CharSequence text = node.getText();
                CharSequence hint = node.getHintText();
                boolean empty = text == null || text.length() == 0 || (hint != null && hint.toString().contentEquals(text));
                holds = step.isEmpty() ? empty
                        : text != null && !empty && (text.toString().equals(step) || node.isPassword() && text.length() == step.length());
                if (!holds) {
                    Thread.sleep(100);
                }
            }
            if (!holds) {
                return false;
            }
        }
        return true;
    }

    static final String FOOTER = "com.google.android.gms:id/suc_footer_button_bar";

    /** The left of the two buttons in Google sign-in's own footer (Skip on the phone-number page), or null. */
    static AccessibilityNodeInfo footerSkip(Walk walk) {
        for (AccessibilityNodeInfo node : walk.nodes) {
            if (FOOTER.equals(node.getViewIdResourceName())) {
                List<AccessibilityNodeInfo> buttons = new ArrayList<>();
                for (AccessibilityNodeInfo item : walk(node).nodes) {
                    if (item != node && item.isClickable() && item.isVisibleToUser() && !inWeb(item)) {
                        buttons.add(item);
                    }
                }
                if (buttons.size() != 2) {
                    return null;
                }
                Rect a = new Rect();
                Rect b = new Rect();
                buttons.get(0).getBoundsInScreen(a);
                buttons.get(1).getBoundsInScreen(b);
                return a.left <= b.left ? buttons.get(0) : buttons.get(1);
            }
        }
        return null;
    }

    static List<Integer> gmsSignInTasks() throws Exception {
        Object service = Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
        List<?> tasks = null;
        for (Method method : service.getClass().getMethods()) {
            if (!"getTasks".equals(method.getName())) {
                continue;
            }
            Class<?>[] types = method.getParameterTypes();
            Object[] args = new Object[types.length];
            args[0] = 100;
            for (int i = 1; i < types.length; i++) {
                args[i] = types[i] == boolean.class ? (Object) false : (Object) 0;
            }
            tasks = (List<?>) method.invoke(service, args);
            break;
        }
        List<Integer> ids = new ArrayList<>();
        if (tasks == null) {
            throw new Refusal("task list unavailable");
        }
        for (Object task : tasks) {
            ids.add(task.getClass().getField("taskId").getInt(task));
            Object top = task.getClass().getField("topActivity").get(task);
            Object base = task.getClass().getField("baseActivity").get(task);
            for (Object component : new Object[] {top, base}) {
                if (component instanceof ComponentName
                        && GMS_SIGN_IN.equals(((ComponentName) component).flattenToShortString())) {
                    ids.add(-1 - task.getClass().getField("taskId").getInt(task));
                }
            }
        }
        return ids;
    }

    /**
     * Google's sign-in web view shows no page URL to accessibility, so a page
     * there cannot be tied to accounts.google.com on its own. This run closes
     * every open Google sign-in, starts a new one in a new task, and fills the
     * entry's email on that task's first email page, which Google Play
     * services loads itself. It then submits the email and fills the password
     * (and, when the broker answers, the code) only on the pages that Google's
     * flow shows next in that task, with no caller step in between. The broker
     * runs it only for consumer Google accounts, which never leave Google.
     */
    JSONObject googleSignIn(JSONObject request) throws Exception {
        if (!bootId().equals(request.getString("boot_id"))) {
            throw new Refusal("device restarted");
        }
        if (speaksPasswords()) {
            throw new Refusal("device lets accessibility read password text (speak_password is not 0)");
        }
        Object service = Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null);
        java.util.Set<Integer> before = new java.util.HashSet<>();
        for (int id : gmsSignInTasks()) {
            if (id < 0) {
                service.getClass().getMethod("removeTask", int.class).invoke(service, -1 - id);
            } else {
                before.add(id);
            }
        }
        run("/system/bin/am", "start", "-a", "android.settings.ADD_ACCOUNT_SETTINGS", "--esa", "account_types", "com.google");
        int taskId = -1;
        for (int attempt = 0; attempt < 100 && taskId < 0; attempt++) {
            Task task = focusedTask();
            // Task ids are numbered per Android user: a new task is one that did not exist before.
            if (task != null && GMS_SIGN_IN.equals(task.activity.flattenToShortString()) && !before.contains(task.taskId)) {
                taskId = task.taskId;
            } else {
                Thread.sleep(200);
            }
        }
        if (taskId < 0) {
            throw new Refusal("Google sign-in did not open");
        }
        JSONArray steps = new JSONArray();
        JSONObject answer = new JSONObject();
        answer.put("ok", true);
        answer.put("steps", steps);
        // Pages before the email page: wait, and skip the phone-number offer with the footer's own button.
        int skips = 0;
        long previous = Long.MIN_VALUE;
        long end = System.currentTimeMillis() + 60000;
        AccessibilityNodeInfo field = null;
        try {
            while (field == null && System.currentTimeMillis() < end) {
                Scene scene = signInScene(taskId);
                if (scene == null) {
                    Thread.sleep(250);
                    continue;
                }
                Walk walk = walk(scene.root);
                field = signInField(walk, "email");
                if (field == null) {
                    AccessibilityNodeInfo skip = hasWebField(walk) ? null : footerSkip(walk);
                    if (skip != null && skips < 2 && walk.nodes.size() > 10) {
                        Thread.sleep(500);
                        if (skip.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                            skips++;
                            Thread.sleep(1500);
                        }
                    } else {
                        Thread.sleep(300);
                    }
                }
            }
        } catch (Refusal refusal) {
            answer.put("stopped_at", "email");
            answer.put("reason", refusal.reason);
            return answer;
        }
        String[] plan = {"email", "password", "code"};
        for (String kind : plan) {
            if (!request.has(kind)) {
                break;
            }
            try {
                if (!"email".equals(kind)) {
                    field = await(taskId, kind, previous, 25000);
                }
            } catch (Refusal refusal) {
                // The screen left this Google sign-in: nothing more is filled.
                answer.put("stopped_at", kind);
                answer.put("reason", refusal.reason);
                return answer;
            }
            if (field == null) {
                answer.put("stopped_at", kind);
                return answer;
            }
            String value;
            if ("code".equals(kind)) {
                // Ask for the code only now, so it is fresh when it is typed.
                out.println(NEED_PREFIX + "code");
                out.flush();
                JSONObject reply = new JSONObject(readRequest());
                value = reply.optString("code", "");
                if (value.isEmpty()) {
                    answer.put("stopped_at", kind);
                    return answer;
                }
            } else {
                value = request.getString(kind);
            }
            if (!setAndConfirm(field, value)) {
                answer.put("stopped_at", kind);
                answer.put("uncertain", true);
                return answer;
            }
            previous = sourceNodeId(field);
            // Submit as the keyboard's Enter would; Google's pages submit on it.
            boolean submitted = field.performAction(android.R.id.accessibilityActionImeEnter);
            steps.put(kind);
            if (!submitted) {
                answer.put("stopped_at", "submit");
                return answer;
            }
        }
        return answer;
    }

    JSONObject context(Scene scene, Walk walk) throws Exception {
        JSONObject context = new JSONObject();
        // Chrome's own address bar: the broker matches its host with Chrome's
        // tab list, which shell processes may not read on the device.
        String addressBar = isChrome(scene.app.packageName) ? addressBarAuthority(scene, walk) : null;
        context.put("address_bar", addressBar == null ? JSONObject.NULL : addressBar);
        context.put("boot_id", bootId());
        context.put("sdk", android.os.Build.VERSION.SDK_INT);
        context.put("speak_password", speaksPasswords());
        context.put("window_id", scene.window.getId());
        CharSequence title = scene.window.getTitle();
        context.put("window_title", title == null ? JSONObject.NULL : clip(title.toString()));
        context.put("package", scene.app.packageName);
        context.put("activity", scene.activity.flattenToShortString());
        context.put("task_id", scene.task.taskId);
        context.put("user_id", scene.task.userId);
        context.put("signers", new JSONArray(scene.app.signers));
        context.put("signer_lineage", new JSONArray(scene.app.lineage));
        context.put("debuggable", scene.app.debuggable);
        context.put("system_app", scene.app.system);
        return context;
    }

    JSONObject inspect(JSONObject request) throws Exception {
        Object[] seen = look(request.optBoolean("wake"));
        Scene scene = (Scene) seen[0];
        Walk walk = (Walk) seen[1];
        JSONArray fields = new JSONArray();
        for (AccessibilityNodeInfo node : walk.nodes) {
            if (isField(node) && fields.length() < MAX_FIELDS) {
                fields.put(describe(node));
            }
        }
        JSONObject answer = new JSONObject();
        answer.put("ok", true);
        answer.put("context", context(scene, walk));
        answer.put("fields", fields);
        answer.put("complete", walk.nodes.size() < MAX_NODES);
        return answer;
    }

    /**
     * The node with this source id in the focused application window. Window
     * ids change with every accessibility connection; source ids stay while
     * the view (or the web element) exists.
     */
    static AccessibilityNodeInfo find(Walk walk, long nodeId) throws Exception {
        AccessibilityNodeInfo found = null;
        for (AccessibilityNodeInfo node : walk.nodes) {
            if (sourceNodeId(node) == nodeId) {
                if (found != null) {
                    throw new Refusal("field id is ambiguous");
                }
                found = node;
            }
        }
        if (found == null) {
            throw new Refusal("field not found in the focused window");
        }
        return found;
    }

    static long parseNode(String id) throws Refusal {
        try {
            return Long.parseLong(id);
        } catch (Exception error) {
            throw new Refusal("invalid field id");
        }
    }

    JSONObject check(JSONObject request) throws Exception {
        Object[] seen = look(request.optBoolean("wake"));
        Scene scene = (Scene) seen[0];
        Walk walk = (Walk) seen[1];
        JSONArray ids = request.getJSONArray("node_ids");
        if (ids.length() < 1 || ids.length() > 2) {
            throw new Refusal("one or two fields required");
        }
        JSONArray fields = new JSONArray();
        for (int i = 0; i < ids.length(); i++) {
            AccessibilityNodeInfo node = find(walk, parseNode(ids.getString(i)));
            if (!isField(node)) {
                throw new Refusal("not a text field");
            }
            fields.put(describe(node));
        }
        JSONObject answer = new JSONObject();
        answer.put("ok", true);
        answer.put("context", context(scene, walk));
        answer.put("fields", fields);
        return answer;
    }

    /** Fields that must be unchanged between pin and fill. */
    static final String[] STABLE = {"node_id", "class", "view_id", "package", "password", "web", "in_frame"};

    JSONObject fill(JSONObject request) throws Exception {
        JSONArray targets = request.getJSONArray("fields");
        if (targets.length() < 1 || targets.length() > 2) {
            throw new Refusal("one or two fields required");
        }
        if (!bootId().equals(request.getString("boot_id"))) {
            throw new Refusal("device restarted since the pin");
        }
        Scene scene = scene();
        JSONObject expectContext = request.getJSONObject("context");
        if (!scene.app.packageName.equals(expectContext.getString("package"))
                || !new JSONArray(scene.app.signers).toString().equals(expectContext.getJSONArray("signers").toString())
                || !scene.activity.flattenToShortString().equals(expectContext.getString("activity"))
                || scene.task.taskId != expectContext.getInt("task_id")) {
            throw new Refusal("focused app changed since the pin");
        }
        if (scene.app.debuggable) {
            throw new Refusal("target app is debuggable");
        }
        Walk walk = settledWalk(scene);
        if (isChrome(scene.app.packageName)) {
            String expected = expectContext.isNull("address_bar") ? null : expectContext.getString("address_bar");
            if (expected == null || !expected.equals(addressBarAuthority(scene, walk))) {
                throw new Refusal("page changed since the pin");
            }
        }
        List<AccessibilityNodeInfo> nodes = new ArrayList<>();
        for (int i = 0; i < targets.length(); i++) {
            JSONObject target = targets.getJSONObject(i);
            JSONObject expect = target.getJSONObject("expect");
            AccessibilityNodeInfo node = find(walk, parseNode(expect.getString("node_id")));
            JSONObject now = describe(node);
            for (String key : STABLE) {
                if (!String.valueOf(now.opt(key)).equals(String.valueOf(expect.opt(key)))) {
                    throw new Refusal("field changed since the pin");
                }
            }
            if (now.optBoolean("in_frame")) {
                throw new Refusal("field is in a frame");
            }
            if (!node.isEnabled() || !node.isVisibleToUser() || !(node.isEditable() || node.isPassword())) {
                throw new Refusal("field is not an enabled, visible text field");
            }
            nodes.add(node);
        }
        if (speaksPasswords()) {
            throw new Refusal("device lets accessibility read password text (speak_password is not 0)");
        }
        // Every check passed: deliver to the exact nodes.
        JSONArray results = new JSONArray();
        boolean delivered = false;
        for (int i = 0; i < nodes.size(); i++) {
            boolean confirmed = setAndConfirm(nodes.get(i), targets.getJSONObject(i).getString("value"));
            // An empty write already changed the field: count any attempt as delivered.
            delivered = true;
            JSONObject result = new JSONObject();
            result.put("accepted", confirmed);
            result.put("confirmed", confirmed);
            results.put(result);
            if (!confirmed) {
                break;
            }
        }
        JSONObject answer = new JSONObject();
        answer.put("ok", true);
        answer.put("delivered", delivered);
        answer.put("results", results);
        return answer;
    }
}
