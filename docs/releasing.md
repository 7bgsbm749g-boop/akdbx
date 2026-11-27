# Releasing akdbx

Each version has one GitHub release for every platform. akdbx is pure Python,
so one `py3-none-any` wheel installs on Linux, Windows and macOS. Environment markers
in `pyproject.toml` select `python-xlib` on Linux, `pywin32` and `comtypes` on Windows, or the PyObjC ApplicationServices and Cocoa bridges on macOS. Do not make separate
Linux and Windows releases: the CLI and broker check each other's version and
capabilities, and one version must mean the same code everywhere. If a frozen
Windows executable is added later, attach it to the same release.

`main` is the release line. `master` must stay equal to `main`; do not merge
pull requests into it separately.

## Cut a release

1. On a branch from `main`, set the new version in `pyproject.toml` and
   `src/akdbx/__init__.py`. Update the version that tests expect:

   ```sh
   git grep -l 'OLD_VERSION' -- tests
   ```

   Add a short entry for user-visible changes where the README or skill
   references describe versioned capabilities.

   The browser extension has its own version, independent of akdbx releases:
   see [Extension version](#extension-version).
   A release that changes the relay client (`src/akdbx/relay.py`) also runs
   the end-to-end test against the real relay server. CI skips it, because
   the server is a separate package:

   ```sh
   git clone https://github.com/7bgsbm749g-boop/akdbx-relay ../akdbx-relay
   python -m pip install ../akdbx-relay 'cryptography>=43,<47'  # keep akdbx's range
   AKDBX_RELAY_SOURCE=../akdbx-relay python -m pytest -q -rs tests/test_relay_integration.py
   ```

   With `AKDBX_RELAY_SOURCE`, the relay gets the certificate through its real
   ACME client from that repository's fake ACME and Cloudflare servers.
2. Merge the pull request into `main` after all checks pass. Fast-forward
   `master` to the same commit.
3. Tag the merge commit and push only the tag:

   ```sh
   git switch main && git pull --ff-only
   git tag -a v1.2.3 -m "akdbx 1.2.3"
   git push origin v1.2.3
   ```

The `Release` workflow then:

- refuses a tag that is not `vX.Y.Z`, that does not match both version
  strings, or whose commit is not on `main`;
- reruns the `Tests` (Linux, Windows and the native macOS broker), `Card safety`, `Password field
  safety` and `Private authenticator import` workflows on the tagged commit;
- builds one sdist and one universal wheel, writes `SHA256SUMS`, and installs
  the wheel into clean Linux, Windows and macOS environments;
- installs that wheel once more and writes the generic browser extension
  (fill extension 0.19.0+, the same files for every user) as release assets:
  `akdbx-extension-chrome-VERSION.zip` and the unsigned
  `akdbx-extension-firefox-VERSION.zip` (`akdbx extension pack`, where
  VERSION is the built extension version);
- has Mozilla sign that Firefox ZIP on addons.mozilla.org (unlisted channel)
  as `akdbx-extension-firefox-VERSION.xpi`, with the API key in the GitHub
  Actions secrets `AMO_JWT_ISSUER` and `AMO_JWT_SECRET` (only that step sees
  them; see [Firefox: how the release signs](firefox.md#how-the-release-signs));
- adds the extension files to `SHA256SUMS` and records a GitHub
  build-provenance attestation for every file;
- publishes the release with the platform table from
  `.github/release-notes.md` and generated change notes.

If any step fails, nothing is published. Fix the problem with a new version;
do not move or reuse a published tag. Two exceptions concern only Mozilla's
signature:

- Without the two secrets the signing step reports `state: "unsigned"`, and
  the release still publishes everything else with a line in its notes that
  it has no signed Firefox add-on.
- AMO review can take minutes. The signing step stops after 20 minutes and
  fails the run with the stage it reached. Re-run the failed jobs of the same
  run: the step finds the version it created on AMO and waits for it again,
  without a second upload. A version that AMO rejected, disabled or deleted
  cannot be used again: bump the fill extension version and cut a new
  release.

The owner sets the secrets in the repository's Actions settings
(`AMO_JWT_ISSUER` is the AMO JWT issuer, `AMO_JWT_SECRET` the JWT secret, from
<https://addons.mozilla.org/en-US/developers/addon/api/key/>). Only the AMO
account that owns the add-on ID `akdbx@akdbx.org` can sign.

## Extension version

The fill extension's version is `"version"` in
`src/akdbx/fill_extension/manifest.json`. `akdbx extension build` keeps it
and adds a fourth part from the built contents (0.35.2+, so Chrome loads a
new service worker for other contents); it does not copy the akdbx version.
That four-part version is also the version of the release's Firefox add-on
that Mozilla signs, and AMO accepts each version string only once: a release
with the same extension contents reuses the signed version that AMO already
has. Bump it in the same pull request as any
change to the files the build writes (every file except `config.js`, which
holds only that version; this
includes the generated `content.js`, which copies the CDP route's DOM checks,
so a change to those checks also changes the extension):

- patch (`0.1.1`) for fixes;
- minor (`0.2.0`) for features;
- major (`1.0.0`) for a protocol break that needs a matching broker.

`tests/fill_extension_fingerprint.json` records a SHA-256 fingerprint of the
built files with the version. `test_extension_version_changes_with_its_contents`
in `tests/test_extension_route.py` fails when the contents change but the
version did not. After the bump, record the new fingerprint:

```sh
AKDBX_UPDATE_EXTENSION_FINGERPRINT=1 python -m pytest -q tests/test_extension_route.py -k contents
```

The test writes the record only when the version is higher than the recorded
one. The extension version is not tied to an akdbx release: a release can ship
the same extension version, and one release can include several extension
bumps.

## Install or upgrade a broker from a release

Download the assets from the release and verify them before use:

```sh
gh release download v1.2.3 --repo 7bgsbm749g-boop/akdbx
sha256sum --check SHA256SUMS
gh attestation verify akdbx-1.2.3-py3-none-any.whl --repo 7bgsbm749g-boop/akdbx
gh attestation verify akdbx-extension-chrome-*.zip --repo 7bgsbm749g-boop/akdbx   # likewise each extension file
```

The extension files need no rebuild on the broker: they are the same generic
build that `akdbx extension build` writes, for every user. Unzip the Chrome
ZIP into the folder that the browser loads (or rebuild it there), and install
the signed Firefox XPI over the old add-on.

Install the wheel, or unpack the sdist into a new immutable release directory
if the host's private deployment notes use source copies. Check that every
runtime dependency in the release's `pyproject.toml` is present before
switching. Keep the previous release directory for rollback.

To set up a new broker after the install, run `akdbx setup` (0.27.0+); see
[Quick start: akdbx setup](../README.md#quick-start-akdbx-setup). It finds the
skill that the wheel ships under `<environment>/share/akdbx/skills/akdbx`.

Restarting a broker locks its vault. Use the host's existing restart procedure
and browser-control lease, confirm that exactly one broker runs the new
version, and give the user the broker's private unlock link. Record the
deployment in the host's private evidence store. Host names, paths, vaults and
service names belong in private deployment notes, not in this repository.
