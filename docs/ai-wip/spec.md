# Multi Mode Spec for `-k`, `--fgraph-extra`, and `-g`

## Goal

Add a **multi mode** for kernel-function tracing so selected targets attach through
`kprobe.multi` family links:

- `kprobe.multi` (entry)
- `kretprobe.multi` (exit)
- `ksession` via kprobe session attach (entry+exit in one session attach type)

This mode applies to:

- `-k` / `--kfunc`
- `--fgraph-extra`
- graph tracing enabled by `-g` (for kernel-function graph targets)

## User-Facing Syntax

Use a new kfunc-style prefix:

- `(m)` => enable multi mode for that function rule

In multi mode, the rule must include an explicitly typed argument selector:

- format: `(m)<kfunc-pattern>:(<arg-type>)<arg-name>`
- example: `-k '(m)*:(struct sk_buff *)skb'`

Examples:

- `-k "(m)*:(struct sk_buff *)skb"`
- `-k "(m)(g)*:(struct sk_buff *)skb"`
- `--fgraph-extra "(m)*:(struct sk_buff *)skb"`

`-g` remains a boolean switch. It does not add new syntax itself, but graph
attachments for kernel-function targets must follow the same `(m)` policy.

## Multi Mode Validation

For any rule using `(m)` (in `-k` or `--fgraph-extra`):

- `<arg-type>` and `<arg-name>` are required
- untyped forms (for example `(m)tcp_v4_connect`) are invalid
- parser must fail fast with a clear message indicating typed argument is
  required for multi mode

## Attach Resolution Rules

For a kernel function marked `(m)`:

- effective entry-only -> attach with `kprobe.multi`
- effective exit-only -> attach with `kretprobe.multi`
- effective entry+exit:
  - if kprobe session attach is supported -> use session attach (`ksession` mode)
  - else -> attach both `kprobe.multi` + `kretprobe.multi`

For kernel functions **without** `(m)`, keep existing trampoline-based attach
behavior (`fentry` / `fexit` / `fsession`).

## Scope of Behavior

- Applies only to kernel-function tracing paths.
- Does **not** change `-p` program tracing attach mode.
- Does **not** change tracepoint attach mode.

## `-g` / Func Graph Behavior

When graph tracing is active (`-g`) and the graph target is a kernel function:

- if the originating rule has `(m)`, graph hooks use the same multi resolution
  rules above
- if no `(m)`, graph hooks keep current trampoline-based behavior

This applies to graph roots from `-k` and extra graph roots from
`--fgraph-extra`.

## Compatibility and Fallback

- If `(m)` is requested but kprobe multi is unsupported, fail fast with a clear
  capability error.
- If entry+exit is needed and session attach is unsupported, degrade to dual
  multi links (`kprobe.multi` + `kretprobe.multi`).
- Existing users not using `(m)` must see no behavior changes.

## Logging / Observability

Debug or verbose logs should clearly state per-target attach mode, e.g.:

- `kprobe.multi`
- `kretprobe.multi`
- `ksession` (kprobe session attach)
- existing `fentry` / `fexit` / `fsession` where applicable

## Non-Goals

- No new standalone flag for multi mode.
- No change to `-g` CLI shape (still boolean).
