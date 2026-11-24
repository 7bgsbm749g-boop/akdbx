# akdbx Android helper

`Helper.java` runs on an Android device with `app_process` as the adb shell
user. The broker sends it one JSON request on standard input and reads one
`AKDBX-ANDROID-RESULT` line. It reads the focused app through UiAutomation,
reports non-secret facts about the app and its text fields, and sets a value
on one exact field (`ACTION_SET_TEXT`) after it checks the field again. See
`src/akdbx/android_route.py`.

The bundled `src/akdbx/android_assets/akdbx-android-helper.dex` is the build of
this source. To rebuild it (JDK 17, Android build-tools 35.0.0, platform 35):

```sh
JAVA_HOME=/path/to/jdk-17 ANDROID_SDK=/path/to/android-sdk android/helper/build.sh
```

Then set `HELPER_SHA256` in `src/akdbx/android_route.py` to the printed hash
and record the source hash once:

```sh
AKDBX_UPDATE_ANDROID_HELPER=1 python -m pytest -q tests/test_android_route.py -k helper
```

CI rebuilds the dex and fails when it differs from the bundled file.
