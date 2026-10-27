# T3 repair-thread handoff

Use this when a client or skill defect blocks an authorized sign-in. The
originating thread owns the original task, live activation and retry loop. The
repair thread owns the isolated source fix, synthetic tests and Git push.

## Dispatch and observe with native T3

Use current `t3-code` tools for local ordinary threads, including another project
on the same server. Do not use fleet scripts for local T3 work. Discover the
registered agentic-kdbx project with `t3_project_list`/`t3_project_read`, then use
`t3_thread_launch` with explicit `projectId`, `workspaceStrategy` and `message`.
For source repair use an isolated worktree based on the intended local commit;
uncommitted parent changes are not copied. The originating repair workflow
explicitly authorizes this ordinary repair conversation. Do not substitute a
provider session, delegated child, database write or legacy import helper.

Include only sanitized reproduction, expected behavior, original sign-in step,
relevant versions, paths and the completion requirements below. Never include
passwords, vault/key contents, handles or live unlock tokens. Inherit configured
model options. Retain returned `threadId` and inspect preparation/turn state with
`t3_thread_read`. Launch has no idempotency key: inspect `t3_thread_list` before
retrying an uncertain launch; do not duplicate the repair.

Use `t3_thread_wait` with the exact run ID for bounded waits and
`t3_thread_read` to read its final messages and actual terminal state. Creation,
idle or error state is not proof of a completed repair. Use supported
`t3_thread_send` to continue an incomplete ordinary repair in the same thread;
do not start another active repair for the same failure. Use a native completion
watch for requested automatic continuation if available. Consult fleet guidance
only for a documented supported fallback or work on another machine.

If tools are initially absent, make one bounded direct MCP attempt; when
configured, use the injected ACP MCP transport fallback. Report remaining tool
limits instead of using retired local fleet/database paths.

## Repair scope and completion evidence

- Reproduce the defect with synthetic credentials and recording targets. Preserve
  unrelated edits and password withholding. Do not recursively spawn repairs.
- Work only in the bound worktree when source-only scope is set. Do not touch
  the live broker, real vault, desktop/browser, services, unlock state,
  permissions/policy or other worktrees. Never claim isolated tests prove a real
  login. Optional native X11 checks need a new isolated test server, never :99.
- Fix source and broken skill/references. Test locked-vault behavior, consumed
  handles, deadlines, controls, modes, generated writes, SSO protocol 1, target
  switches, partial failures and secret-free responses/logs. Run the relevant
  existing regressions. Use the resource-manager queue and bounded batches for
  heavy jobs; do not change resource settings.
- Store evidence in the project's ignored `evidence/` directory. Validate with
  `python3 /home/ubuntu/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/agentic-kdbx`.
- Review Git status/remote, commit only the patch and push the configured repair
  branch. Never include vaults, tokens, secret-bearing artifacts or unrelated
  work. Return cause/design/limits, changed files, test/evidence results, full
  commit SHA, exact push destination/result and parent activation/use steps.
  Report a missing destination or push failure; do not invent one.

## Parent update and resume

Read the actual repair final before activation. Verify the reviewed commit is in
the CLI checkout without overwriting dirty work. An editable install affects new
CLI processes but not an already running broker. The parent owns preservation of
the latest verified encrypted state and one coordinated normal restart/private
unlock with unchanged deployment configuration. Never hotpatch, start a second
broker/unlock service, export a key, bypass policy, or approve an obsolete prompt.

For target-pinned fill, follow [activation and use](target-fill.md). Check both
CLI version and running broker capability, reread the skill, and obtain fresh
search and target handles. Resume the original authorized sign-in and verify
non-secret authenticated state without reading password fields. Continue the
original task after sign-in succeeds. Keep an external dependency such as MFA
or private unlock explicit; an isolated passing test is not a sign-in result.
