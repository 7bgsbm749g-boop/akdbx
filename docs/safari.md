# Safari extension on macOS (0.48.0+)

Safari 26 or newer uses a local akdbx broker on the same Mac. Safari is not
available on Linux or Windows. This extension adds no remote broker connection
and needs no browser debugging port.

The extension uses the existing pairing, sealed values and retained document
targets. A private native helper forwards sealed messages to the local broker.
The helper checks the caller and broker user, private runtime paths and ACLs.
It does not open the vault or the broker's TLS key. The Safari app extension
stays sandboxed and has no runtime-file exception.

## Build and enable

1. Configure and start the broker with [the macOS setup](macos.md). Use its
   default socket, `~/Library/Application Support/akdbx/run/s`.
2. Install full Xcode and select it as the active developer directory. The
   Command Line Tools package alone does not supply the Safari app packager.
3. Build into a new app path, using the broker's configured private-page origin:

   ```sh
   akdbx --unlock-origin https://YOUR-BROKER-ORIGIN extension safari-app --output "/absolute/path/akdbx Safari.app"
   open "/absolute/path/akdbx Safari.app"
   ```

4. In Safari settings, enable **Show features for web developers** under
   **Advanced**, then **Allow unsigned extensions** under **Developer**. This
   developer setting resets when Safari quits. Under **Extensions**, enable
   akdbx and permit access to the sites where you will use it.
5. Open the akdbx toolbar popup. Open its pairing page, check that both show the
   same code, then enter the master password on the broker's private HTTPS page.
   Agents can then use `--route extension`.

The command builds and signs a local developer app without an Apple Developer
account. This release does not supply a notarized app or an App Store listing.
Safari requires its developer setting and extension permission before it runs
this build. The builder does not change Safari settings or enable the extension.

`extension build --browser safari --output FOLDER` builds JavaScript resources
only. A raw extension folder has no native app handler and cannot connect to
the broker. Use `extension safari-app` for local broker fills. Safari does not
use `extension install` or a Chromium/Firefox native-host manifest.

## Update and limits

Build an update into another new `.app` path. The builder refuses to replace
an existing path. Quit the containing app, replace the old app through Finder,
then load the updated extension and pair again. Do not use an old pairing
after a broker or Safari restart.

The macOS broker remains extension-only: native desktop-field delivery, CDP
and guided setup are unavailable. Custom broker socket paths are not supported
by this Safari build. The separate authenticator QR capture extension remains
Chromium-only.

Safari must provide the document and DOM APIs required by a pin. Unsupported
checks cause a refusal. No password is sent through keyboard input or the
clipboard, and the agent receives only a receipt.

Apple documents [running unsigned Safari extensions](https://developer.apple.com/documentation/safariservices/running-your-safari-web-extension)
and [native app messaging](https://developer.apple.com/documentation/safariservices/messaging-between-the-app-and-javascript-in-a-safari-web-extension).
