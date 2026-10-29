**Security audit — akdbx — 18 September 2026**

Audited revision: `d77df04825622df1e7992a3d3b0140ef552ce72f` (`0.1.0`). The working tree was clean at the start. This audit adds this report and a synthetic reproduction suite; it does not change production behavior.

**Assessment**

The narrow RPC interface successfully withholds the password field from normal responses, and several useful safeguards are implemented correctly. However, I would address the keyboard-delivery defects and unlock-backend trust before relying on this for an unattended, high-value vault. The implementation is a convenience broker for a trusted agent on a trusted desktop, not an isolation boundary that prevents an agent from obtaining secrets.

The review identified **nine findings: two High, five Medium, and two Low**. One High finding is a conditional deployment attack inferred from the verified proxy configuration and backend design; it was not attempted against the deployed service. The other High finding and the principal availability/rate-limit failures were reproduced with synthetic data. Severity reflects this application's local/tailnet deployment, not an assumption that its Unix socket is publicly reachable.

| ID | Severity | Finding | Evidence |
| --- | --- | --- | --- |
| F1 | High | Credential control characters become Enter/Tab keystrokes | Reproduced using the installed typing implementation |
| F2 | High, conditional | A replacement local backend can solicit the master password at the trusted HTTPS origin | Source review and read-only deployment evidence; attack not performed |
| F3 | Medium | CLI trusts an unauthenticated socket and arbitrary unlock URL | Fake private test server accepted; cross-user variant conditional |
| F4 | Medium | Concurrent unlock requests bypass the five-failure limit | Eight simultaneous attempts entered the opener |
| F5 | Medium | Unlock HTTP connections have no application timeout or worker bound | Six incomplete requests held six blocking accepted sockets |
| F6 | Medium | Unix client failures can block or terminate the entire broker | Idle connection, disconnect, and oversized response reproduced |
| F7 | Medium | A queued fill executes after its caller times out and disconnects | Reproduced with a recording keyboard backend |
| F8 | Low | Socket replacement and cleanup lack exclusive ownership | Two brokers replaced/removed each other's socket path |
| F9 | Low | Expired handles accumulate without a bound | 1,000 expired handles remained in the broker |

**Scope and evidence**

Reviewed all five production Python files, packaging, all existing tests, the README, and repository agent instructions/setup references. Inspected the relevant installed PyKeePass and pynput implementation, checked installed runtime dependencies against PyPI's release-specific advisory metadata, and inspected only the relevant Tailscale Serve mapping and its Funnel flag.

Validation used new temporary Unix sockets, random loopback HTTP ports, synthetic KDBX files, and a recording/dummy keyboard backend. No real vault or key file was read, no master-password interaction was observed, no live broker request or attack was sent, and no desktop input or deployment change was made. The fake identity headers used in the tests were sent only to audit-created synthetic servers.

Results:

- Existing suite: `.venv/bin/pytest -q` → **34 passed in 20.29 seconds**.
- Audit suite: `.venv/bin/pytest -q audits/2026-09-18/reproduce.py` → **13 passed in 12.19 seconds**.
- The audit assertions confirm vulnerable behavior and documented limitations. They are not regression tests demonstrating a fix, and they are outside the normal `testpaths = ["tests"]` collection.
- Python was 3.14.4; the main installed dependencies were PyKeePass 4.2.0 and pynput 1.8.2.
- The deployed unlock mapping forwards HTTPS port 9443 to `http://127.0.0.1:43128`. Its own `AllowFunnel` flag was false. Other services' Funnel settings do not establish exposure of this port.
- A bounded scan of the 18 tracked files found no KDBX/key containers, private-key blocks, matching GitHub/AWS token patterns, or literal live-length unlock tokens. This is not an exhaustive secret scan of history or ignored files.

The tailnet ACL/grants policy, other users' access, OS hardening, browser security, host compromise, package provenance, and the cryptographic implementations themselves were not independently audited. No claim of public internet exploitability or existing compromise is made.

**Trust boundaries**

The master password travels from the user's device through Tailscale HTTPS termination to a plain HTTP loopback backend. That backend constructs a PyKeePass object in the broker process. A local CLI uses a filesystem-protected Unix socket to search metadata and obtain handles. A fill sends global keystrokes to whichever application currently receives keyboard input.

Consequently, the trusted computing base includes the OS account, Python environment and dependencies, Tailscale configuration/proxy, desktop session, destination application, and agent's targeting decisions. A process with the broker's OS privileges can ordinarily bypass this API; a browser page receiving a password can also read its input. Both limitations are acknowledged in the README. I do not count either as a newly discovered authentication bypass.

- [ ] **F1 — High: saved credential control characters can redirect input or submit a form**

Code: [broker.py:46](../../src/akdbx/broker.py#L46), [broker.py:146](../../src/akdbx/broker.py#L146).

`PynputTyper.type_text()` delegates directly to `Controller.type()`. The installed pynput 1.8.2 maps newline and carriage return to `Key.enter` and tab to `Key.tab` before pressing/releasing each key. The broker does not validate either credential before delivery. The existing mock-based “literal text” test replaces `Controller.type()` itself, so it cannot detect this behavior. The real implementation is also visible in [pynput's controller source](https://github.com/moses-palmer/pynput/blob/master/lib/pynput/keyboard/_base.py).

The reproduction uses the actual installed `Controller.type()` with recorded key presses and a dummy backend. A synthetic password `x\ny\tz\r` produces `x`, Enter, `y`, Tab, `z`, Enter, and the broker returns a successful fill receipt.

An imported or edited username/password containing these characters can alter focus or submit the form. In login mode, a control character in the username can disrupt the expected single-Tab transition before the password is typed. This can expose the password to a visible field or another application state. No shell metacharacter interpretation is involved; the problem is keyboard-event interpretation. Exploitation requires such an entry to be selected, or an accidental control character in a legitimate entry.

**Fix:** validate all fields needed for a fill before sending any key. Reject CR/LF/TAB and unsupported control characters with a generic error and no partial delivery. Do not silently remove or rewrite password characters. Add tests using the real `Controller.type()` conversion layer with recorded `press`/`release`, including a bad username in login mode. Correct the README/skill's unconditional “never submits” guarantee until enforced.

- [ ] **F2 — High, conditional: persistent Serve mapping does not authenticate the unlock backend**

Code/configuration: [cli.py:60](../../src/akdbx/cli.py#L60), [web_unlock.py:139](../../src/akdbx/web_unlock.py#L139), [VPS setup](../../skills/akdbx/references/vps-setup.md).

The documented persistent Serve mapping and the observed live configuration point to a fixed, unprivileged loopback TCP port. The Python listener exists only for the broker's lifetime. No upstream TLS identity, protected socket ownership, or persistent supervisor-held listener ties the HTTPS origin to this particular broker.

If an untrusted local process can bind that port while the broker is stopped, it can supply a lookalike unlock page through the existing trusted Tailscale HTTPS origin. The user might revisit a previously issued link and enter the master password. A replacement page can accept any token: the real token check is inside the replaced application. The attacker does not need to compromise Tailscale TLS or know the original token beforehand. An ordinary different OS user can bind an available high TCP port in a shared network namespace unless additional host policy prevents it.

This is a **deployment attack inference**, not a performed exploit. The relevant mapping was confirmed read-only; no attempt was made to bind port 43128, replace the live backend, or capture a submission. It requires a local attacker, an available port, and a subsequent user submission. It does not let an attacker seize an already bound listener. Unlike the documented malicious-same-user exclusion, this can matter for a different local UID.

**Fix:** give the upstream a verifiable identity or protected, persistent endpoint. Options include an authenticated HTTPS upstream with proper certificate verification, or a supervised proxy/Unix-socket arrangement whose sensitive endpoint cannot be replaced by other users. Socket activation must reserve the listener across broker restarts, and needs implementation support. Coordinate proxy lifecycle with broker lifecycle and keep the host free of untrusted workloads meanwhile. Merely trusting the displayed Tailscale hostname, adding a form token, or checking the request's identity header does not authenticate a replacement backend.

Tailscale's documentation describes Serve as a proxy to a local service and explicitly notes that localhost limits header spoofing to other local services; it does not promise application identity for an arbitrary local listener. [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve#identity-headers).

- [ ] **F3 — Medium: client does not authenticate its socket or constrain the unlock URL**

Code: [cli.py:15](../../src/akdbx/cli.py#L15), [cli.py:21](../../src/akdbx/cli.py#L21), [cli.py:81](../../src/akdbx/cli.py#L81).

The CLI connects to a pathname and prints the returned dictionary without checking directory ownership/mode, symlinks, server peer credentials, or the scheme/origin of `unlock_url`. With `XDG_RUNTIME_DIR` absent, the predictable fallback is `/tmp/akdbx-UID/akdbx.sock`.

The test creates an intentionally world-writable test directory/socket and a fake server returning an arbitrary `https://phishing.example.invalid/` link. `request()` accepts it. The cross-user variant is inferred: another user could pre-create the predictable fallback before the victim's private directory exists. The real broker would fail its `chmod` on an attacker-owned directory, but that does not protect a CLI `status` request made before startup. The normal existing `/run/user/UID` boundary substantially reduces this exposure.

**Fix:** require a trusted, correctly owned private runtime directory, reject unsafe/symlinked paths, and check Unix peer credentials against the configured broker UID. Validate responses and only present an HTTPS unlock URL matching an independently configured expected origin. If the broker later runs under a separate account, peer verification must use that configured identity rather than blindly requiring the caller's UID. URL validation alone does not address F2's same-origin replacement attack.

- [ ] **F4 — Medium: concurrent requests bypass unlock throttling**

Code: [web_unlock.py:34](../../src/akdbx/web_unlock.py#L34), [web_unlock.py:98](../../src/akdbx/web_unlock.py#L98), [web_unlock.py:114](../../src/akdbx/web_unlock.py#L114).

`allowed_attempt()` checks a failure list under a lock, then releases it before expensive key derivation. A failure is recorded only when the opener returns an error. ThreadingHTTPServer can admit many requests before any has completed, so each sees fewer than five failures.

The bounded test holds eight synthetic opener calls in progress and observes all eight admitted. Every call returns 401 after release; a subsequent sequential request gets 429. This demonstrates the race while also confirming that the sequential limiter works.

Prerequisites are a valid unlock token and ability to reach the endpoint with an accepted identity header. A tailnet request receives that header from Serve; a direct local caller can supply it. The test does not establish token theft or a master-password bypass. The impact is parallel online guessing and excessive CPU/memory use from simultaneous KDFs.

**Fix:** atomically reserve a budget slot before key derivation, limit concurrent unlock work (preferably one operation for this single vault), and recheck locked/token state inside the serialized operation. Bound both total request admission and per-identity attempts. Do not hold a state lock while waiting indefinitely for a slow request body. Add an eight-request regression test that proves excess requests never enter the opener.

- [ ] **F5 — Medium: HTTP worker/socket lifetime is unbounded**

Code: [web_unlock.py:108](../../src/akdbx/web_unlock.py#L108), [web_unlock.py:139](../../src/akdbx/web_unlock.py#L139).

The server creates a thread per connection and sets no accepted-socket timeout or worker limit. A client can leave headers incomplete before identity/token validation, or supply a valid token and a declared body length while withholding the body. `MAX_BODY` limits bytes, not waiting time or thread count. Invalid tokens do not prevent the pre-handler header-read case.

The reproduction opens only six connections to a new local test server and leaves the header block incomplete. All six accepted sockets are blocking (`gettimeout() is None`) and remain open until test cleanup. No resource-exhaustion flood was performed.

This is directly reachable by local processes sharing the network namespace, regardless of Unix-socket file permissions. Remote exploitability of the incomplete-header variant through Serve depends on its buffering and timeout behavior and was not verified. Do not infer a public Slowloris exploit from the local test. Python itself cautions that `http.server` supplies only basic security protections. [Python http.server documentation](https://docs.python.org/3/library/http.server.html).

**Fix:** add bounded header/body/connection deadlines and a connection/worker cap, or use a server stack that provides them. Preserve generic errors and avoid logging form bodies. Test cleanup and resource recovery after incomplete requests, including requests that never reach authorization.

- [ ] **F6 — Medium: ordinary socket failures can hang or kill the broker**

Code: [broker.py:179](../../src/akdbx/broker.py#L179), [broker.py:187](../../src/akdbx/broker.py#L187), [broker.py:191](../../src/akdbx/broker.py#L191), [protocol.py:15](../../src/akdbx/protocol.py#L15).

The Unix server processes one connection at a time. Its listener timeout does not set a timeout on accepted sockets. An idle client blocks all subsequent requests. Only `ProtocolError` around receive/dispatch is handled; sending the response is outside that handler. A closed client causes `BrokenPipeError` and unwinds the entire server, removing its socket. The CLI then shuts down the unlock server as well.

Three bounded cases were reproduced: an incomplete four-byte request header blocked a second client's ping; connecting and immediately closing terminated the broker; and a synthetic 65,536-character title caused search response serialization to exceed `MAX_MESSAGE`, raising an uncaught `ProtocolError` and terminating the broker. The response-size guard exists but is applied too late for graceful error handling.

A malicious same-UID process is outside the stated security model, so these are not elevated to remote critical vulnerabilities. Nevertheless, normal client cancellation/timeouts and a large imported metadata field trigger the same denial of service, requiring a fresh private unlock.

**Fix:** bound per-connection receive/send time, isolate failures to the current connection, catch expected disconnects on both directions, and enforce a response budget before sending. Limit each metadata field and the total encoded search response. Return generic bounded errors for unexpected entry access errors without echoing credential values. Keep keyboard operations serialized even if metadata requests become concurrent.

- [ ] **F7 — Medium: abandoned queued requests can still type secrets**

Code: [cli.py:23](../../src/akdbx/cli.py#L23), [broker.py:185](../../src/akdbx/broker.py#L185), [broker.py:135](../../src/akdbx/broker.py#L135).

The client waits five seconds, but a fill request contains no delivery deadline or cancellation state. An earlier client can block the single server while a complete fill waits in the queue. When the first client releases it, the server reads the buffered request and types even if the fill caller has timed out and closed its connection. Only sending the receipt reveals the disconnect, after secret delivery.

The reproduction queues a fill behind a deliberately incomplete ping, uses a shortened 150 ms client timeout, closes the fill connection, then completes the ping. No text was typed before timeout; the synthetic password was typed after the caller had disconnected. The subsequent receipt raised `BrokenPipeError`.

This is more specific than the acknowledged possibility that typing is already in progress during a timeout. Input can **start later**, after the user/agent moves on to another field or application. Wrong-destination disclosure depends on that focus change. The current skill warns about uncertain fills but cannot cancel them.

**Fix:** carry and enforce a short start deadline, reject stale queued requests before reading credentials, bound queue waiting, and check connection liveness immediately before delivery. Connection checking alone is racy. A robust design also binds delivery to a verified destination and provides explicit operation state/cancellation, distinguishing “not started” from “possibly partial.” Do not fix this solely by extending the client timeout or retrying automatically.

- [ ] **F8 — Low: socket lifecycle can disrupt another live broker**

Code: [broker.py:167](../../src/akdbx/broker.py#L167), [broker.py:169](../../src/akdbx/broker.py#L169), [broker.py:195](../../src/akdbx/broker.py#L195).

Startup unlinks any existing socket without proving it stale. Shutdown unlinks the pathname without confirming that it still refers to this server's inode. In the test, a second broker replaced a live first broker's pathname; stopping the first then removed the second's socket while the second server remained alive. The default HTTP-port collision often prevents this through the normal CLI, but it remains possible with separate unlock ports or direct library use.

The same setup unconditionally chmods the socket's existing parent to 0700. A custom socket under an unrelated shared/project directory can unexpectedly change that directory's access permissions. The setup reference already warns about both behaviors, which lowers surprise but does not enforce safety.

**Fix:** use a dedicated owned runtime subdirectory, reject unsafe existing permissions instead of rewriting arbitrary parents, hold a lifecycle lock, refuse a live endpoint, and record/check socket identity before cleanup. Handle stale cleanup without introducing a check/unlink race.

- [ ] **F9 — Low: handle expiration does not release stored handles**

Code: [broker.py:92](../../src/akdbx/broker.py#L92), [broker.py:99](../../src/akdbx/broker.py#L99), [broker.py:125](../../src/akdbx/broker.py#L125).

Every match stores a new handle. Expiration is checked only when that exact handle is consumed. No search-time cleanup, timer, or size cap removes unused expired handles. The reproduction advances a fake clock beyond every expiry while searching 1,000 times; all 1,000 expired handles remain.

This does not make an expired handle usable: expiry enforcement works. It creates unbounded memory growth in a long-lived process, up to twenty allocations per search. Same-user resource abuse is already outside the isolation model, but ordinary repeated agent searches can accumulate state indefinitely.

**Fix:** prune expired handles on issuance/resolution and cap outstanding handles. Test both expired-handle rejection and bounded retained state.

**Additional security limitations and hardening opportunities**

- [ ] **Destination and scope are policy, not enforced authorization.** There is no origin/window binding, per-entry allowlist, agent identity, or workflow scope. An empty search returns up to twenty entries, and successive queries can reach other groups. A five-minute handle authorizes its selected entry, not a specific destination or fill mode. Keep a small dedicated automation vault/group if using this design; stronger containment needs an independently enforced delivery boundary. The existing skill correctly says metadata is untrusted data and a substring match is not proof of a site.
- [ ] **Metadata is not inherently non-secret.** Title, username, URL, and group are returned verbatim. The synthetic KDBX check confirmed that a title marked `Protected="True"` is returned after save/reopen, and a recycled entry remains searchable. KeePass memory protection is not automatically an API authorization policy, so this is not claimed as a cryptographic bypass. Still, define a deliberate disclosure policy and exclude recycled/expired/disabled entries by default if those states are meant to withdraw automation access. Check KeePass auto-type settings rather than assuming this independent autofill implementation honors them.
- [ ] **The master password remains reachable in memory.** Clearing the handler's local `password` variable does not clear `raw`, `values`, or PyKeePass's retained password. A real synthetic-vault test confirmed `broker.vault.password` still equals its master password after unlock. The vault is never idle-locked; decrypted entries and key material remain for process lifetime. The README acknowledges memory limits and lifetime unlock, so this is hardening rather than a new remote disclosure. Avoid retaining the master password when it is unnecessary for a read-only broker; add explicit/idle locking, disable sensitive core dumps, and investigate swap/crash-capture policy. Python string reassignment is not secure erasure. [PyKeePass source](https://github.com/libkeepass/pykeepass/blob/master/pykeepass/pykeepass.py).
- [ ] **Identity is any nonempty header.** There is no owner allowlist. Direct local requests can spoof the header; one synthetic test demonstrates acceptance with the test token and synthetic opener. That does not bypass the real vault password or the 256-bit URL token. Through Serve, Tailscale strips and supplies identity headers; this review found no evidence of remote header spoofing through the real proxy. Define who may unlock through ACLs and an explicit application allowlist if multiple tailnet users or node shares exist. [Tailscale identity headers](https://tailscale.com/docs/features/tailscale-serve#identity-headers).
- [ ] **Unlock links have no time expiry.** They rotate on successful unlock but otherwise live for the process lifetime and are printed on startup/returned to callers. Treat their presence in private agent transcripts as intentional credential-like disclosure, not proof they cannot be persisted. Add a short expiry/renewal mechanism and minimize logging/persistence. A leaked link alone does not decrypt the vault.
- [ ] **Dependency installation is not reproducible.** `pyproject.toml` allows broad ranges, including an unbounded newer setuptools build backend; there is no deployment lockfile, hash-pinned requirement set, or tracked CI/security scanning. Package compromise would execute within a process holding the entire vault. Add a reviewed deployment lock and automated advisory checks; do not treat a clean advisory lookup as provenance verification.
- [ ] **Secret-bearing files are not specifically excluded from Git.** The current `.gitignore` excludes build/test directories but not arbitrary KDBX/key-file locations. No tracked containers were found. Add deliberate exclusions for real vault/key artifacts and a pre-commit/CI secret check without blocking intentional synthetic fixtures.

**Dependency advisory check**

Queried the exact installed releases' `vulnerabilities` fields at `https://pypi.org/pypi/<name>/<version>/json`. All fifteen runtime dependency queries completed and returned empty lists on the audit date. These are release-specific advisory results, not a claim that every dependency is vulnerability-free. The API's semantics are documented by [PyPI](https://docs.pypi.org/api/json/#known-vulnerabilities).

| Package | Installed version |
| --- | --- |
| pykeepass | 4.2.0 |
| pynput | 1.8.2 |
| argon2-cffi | 25.1.0 |
| argon2-cffi-bindings | 26.1.0 |
| cffi | 2.1.1 |
| construct | 2.10.70 |
| evdev | 2.0.0 |
| importlib_metadata | 9.0.1 |
| lxml | 6.1.3 |
| pycparser | 3.0 |
| pycryptodomex | 3.23.0 |
| PyOTP | 2.10.0 |
| python-xlib | 0.33 |
| six | 1.17.0 |
| zipp | 4.1.0 |

The interpreter, OS libraries, Tailscale, browser, test tooling, and build-time packages were not included in that runtime-package advisory result. Installed dependency sources were inspected selectively; a complete third-party code audit was not performed.

**Controls that held up**

The broker starts locked and rejects search/fill while locked. Search excludes the password field; the RPC exposes no reveal/export/arbitrary-field method. Handles are random, process-specific, short-lived, and consumed on the first fill attempt, including invalid mode or typing failure. Exact membership in the server-side handle table provides validation; not recomputing the embedded HMAC does not by itself permit forged handles. Keyboard exceptions are replaced with generic errors after credential access.

The tested socket/directory modes are 0600/0700. HTTP binds only to allowed loopback names; a non-loopback address is rejected. The unlock token uses 32 random bytes and constant-time comparison, rotates after successful unlock, and is required alongside the identity header. Page identity text is escaped; responses include no-store, CSP with frame/form restrictions, nosniff, and no-referrer. HTTP request logging is disabled. The code uses JSON rather than pickle/eval and contains no shell-command execution path. KDBX reading and cryptography are delegated to PyKeePass rather than reimplemented.

No demonstrated unauthenticated remote password-reveal endpoint, KDBX cryptographic bypass, shell injection, or routine password-bearing response was found. These observations do not remove the keyboard-delivery and deployment risks above.

**Recommended work order and acceptance criteria**

1. **Credential delivery:** fix F1 and F7 first. Test that unsafe fields cause zero key events, stale/abandoned queued fills never start, and any remaining uncertain in-progress state is reported without encouraging duplicate fills. Preserve the user's intended lack of per-fill terminal prompts.
2. **Unlock trust:** address F2/F3 with an authenticated/protected upstream and verified local server identity; constrain HTTPS origins and add an explicit unlock-owner policy where appropriate. Verify behavior during stopped/restarted broker states, not only steady state.
3. **Availability:** fix F4–F6 with atomic admission, one bounded KDF operation, worker/socket deadlines, connection-local error handling, and bounded response construction. Verify the broker remains responsive after malformed, slow, disconnected, and oversized requests using synthetic servers.
4. **Lifecycle and scope:** fix F8/F9, add idle/explicit lock and minimal-vault scope, and define recycled/expired/disabled/protected-metadata handling. Test that one process cannot remove another's endpoint and that expired handles do not accumulate.
5. **Maintenance:** lock deployment dependencies, add advisory/secret checks, update the README and skill guarantees, and retain adversarial tests as fixed-behavior regressions. Restarting a live broker to use future fixes will require a fresh user unlock; this audit did not restart it.

All nine findings remain unresolved in the audited production code. The provided reproduction suite and exact code references make a follow-up remediation review concrete.
