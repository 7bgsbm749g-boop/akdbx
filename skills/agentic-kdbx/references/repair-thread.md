# T3 repair-thread handoff

Use this when a client or skill defect blocks an authorized sign-in. The originating agent owns the original task and retry loop; the repair thread owns the scoped fix, tests, and Git push.

## Dispatch on the VPS

Read the installed [personal-fleet skill](/home/ubuntu/.codex/skills/personal-fleet/SKILL.md) for the current T3 adapter contract. Use a real T3 thread, not a provider subagent or `codex exec` substitute.

Discover the current project registration:

```bash
/home/ubuntu/.local/bin/t3-fleet --host local projects
```

Select `agentic-kdbx` with root `/home/ubuntu/projects/agentic-kdbx`. As verified on 2026-09-18, its ID is `5050d7b3-8e05-4279-8cce-db811e4d9ec7`; rediscover it rather than assuming this ID is permanent. The `--host local` commands below are for execution on the VPS. From another fleet machine, select `--host vps` instead.

Prepare a temporary prompt file containing only sanitized reproduction details, the failing sign-in step, expected behavior, relevant paths, tests to reproduce the issue, and the required completion evidence below. Then dispatch:

```bash
/home/ubuntu/.local/bin/t3-fleet --host local start \
  --project /home/ubuntu/projects/agentic-kdbx \
  --title 'KeePass repair: SHORT_FAILURE_DESCRIPTION' \
  --prompt-file /absolute/path/to/sanitized-repair-prompt.txt
```

Inherit the project's model/runtime selection. Retain the request ID and thread ID. If dispatch transport fails, retry identical parameters with the same `--request-id`; do not blindly create a duplicate thread.

## What the repair thread must do

Include these requirements in its task:

- Reproduce the reported client/instruction defect. Work in the `agentic-kdbx` project, preserving unrelated edits. Coordinate with the originating agent before touching its live broker or desktop target.
- Fix the underlying behavior. Correct `skills/agentic-kdbx/SKILL.md` and linked references when the instructions contributed to the failure. This is explicitly authorized by the user. Do not spawn another repair thread for the same issue.
- Exercise the failure and repaired path using a synthetic KDBX. Run relevant existing tests (`.venv/bin/pytest -q`) and add a regression test when it demonstrates the bug. Check locked-vault rejection, short-lived consumed handles, fills without terminal input, keyboard delivery, and password withholding in responses and logs. Use isolated sockets and a recording keyboard backend for a source-only repair. Actual desktop verification belongs to the originating workflow when the repair scope excludes live broker/desktop access; do not interact with those targets from the repair thread.
- Validate skill changes with `python3 /home/ubuntu/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/agentic-kdbx`.
- Inspect Git status and the configured remote, commit only the intended patch, and push through the project's established branch workflow. Never include real KDBX/key files, tokens, generated secret-bearing artifacts, or unrelated work. Report any push failure explicitly.
- Return the cause, changed files, tests and results, commit SHA, remote/branch pushed, local update/restart requirements, and any unresolved blocker. The original agent must be able to verify that the running version includes the fix.

At the time this instruction was added (2026-09-18), this directory was registered as a T3 project but was not yet a Git repository. Recheck during a repair. If Git or a remote is still missing, complete the local repair and tests, then report the missing push destination and obtain that configuration from the user. Do not invent a remote or claim the patch was pushed.

## Wait, update, and resume

```bash
/home/ubuntu/.local/bin/t3-fleet --host local wait THREAD_ID --timeout 40
/home/ubuntu/.local/bin/t3-fleet --host local read THREAD_ID
```

Repeat bounded waits while the repair is running, with concise user progress updates. The adapter's `read` output exposes messages, turn/session errors, and activity. Inspect the final result and actual completion state, including tests and the push result. The adapter described by personal-fleet does not support sending into an existing thread: if further work is required and no supported T3 follow-up tool is available, create a successor thread with the prior thread ID, commit, and remaining failure, after the earlier thread has stopped.

Verify the patch is present in the checkout used by the CLI; do not blindly pull over a dirty shared worktree. An editable install can see changed source on a new CLI invocation, but the existing broker keeps previously loaded code until restarted. The originating workflow owns the live restart: stop the correct old broker, including any pending obsolete approval prompt, before starting the patched broker and requesting a fresh user-facing web unlock. Per-fill terminal approval has been removed; `--yes-on-fill` is now a deprecated no-op. Read corrected skill instructions before retrying with a new handle and verified target focus.

Resume the original sign-in step and verify authenticated state without reading password fields. Repeat this handoff for subsequent client-caused failures until sign-in succeeds, then carry on with the original task. A passing isolated test alone is not the final sign-in outcome.
