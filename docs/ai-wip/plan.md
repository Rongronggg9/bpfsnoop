# Multi Mode Implementation Plan

Date: 2026-02-04

This plan follows `docs/ai-wip/spec.md` and the requested execution order.

## 1) Implement BPF prog for multi mode (feature parity with `bpfsnoop_fn`)

Goal: a kprobe-program-based data path that supports the same output/filter
features currently provided by `bpfsnoop_fn`:

- session semantics (entry/exit pairing, duration, cookie)
- arg filter / arg output
- packet filter / packet tuple output
- LBR output
- stack output
- function arg buffer output (entry/exit)

Plan:

1. Add new BPF C program(s), e.g. `bpf/bpfsnoop_kmulti.c`:
   - section(s) suitable for kprobe-multi attach (`kprobe.multi` / `kretprobe.multi` / session path)
   - use `bpf_get_func_arg_cnt`, `bpf_get_func_arg`, `bpf_get_func_ret` instead of relying on trampoline layout
   - preserve current event format compatibility (`bpf/bpfsnoop_event.h`) so Go-side reader logic needs minimal changes
2. Add or reuse config struct for kmulti path (similar to `bpfsnoop_cfg.h`) for toggles and buffer sizes.
3. Reuse existing shared helper headers where possible:
   - `bpfsnoop_arg_filter.h`
   - `bpfsnoop_arg_output.h`
   - `bpfsnoop_fn_args_output.h` (or add a kmulti-specific variant if needed)
   - `bpfsnoop_pkt_filter.h`
   - `bpfsnoop_pkt_output.h`
   - `bpfsnoop_sess.h`
   - `bpfsnoop_lbr.h`
   - `bpfsnoop_stack.h`
4. Add loader plumbing in Go build-generated path (same pattern as current `LoadBpfsnoop` / `LoadGraph` / `LoadInsn`).
5. Validate verifier constraints early (especially helper availability and bounded loops).

## 2) Detect kprobe features

Goal: runtime capability gating for:

- kprobe multi attach
- kprobe session attach
- helper assumptions required by kmulti data path

Plan:

1. Extend `internal/bpfsnoop/bpf_feature.go`:
   - add booleans for multi/session capabilities (e.g. `hasKprobeMulti`, `hasKprobeSession`)
   - keep existing `hasFsession` detection for trampoline path
2. Capability checks:
   - enum presence checks in BTF for attach types:
     - `BPF_TRACE_KPROBE_MULTI`
     - `BPF_TRACE_KPROBE_SESSION`
   - optionally add a minimal runtime attach probe if enum check is insufficient
3. Add clear error messages for requested `(m)` mode when capability is missing.

## 3) Add the new tracing attachment

Goal: attach kernel-function tracing through multi links when `(m)` is selected.

Plan:

1. Extend tracing state structs in `internal/bpfsnoop/bpf_tracing_func.go`:
   - store links created via `link.KprobeMulti` / `link.KretprobeMulti`
   - keep close behavior consistent with existing tracing lifecycle
2. Implement a multi attach path:
   - entry-only -> `link.KprobeMulti`
   - exit-only -> `link.KretprobeMulti`
   - entry+exit -> prefer session (`Session: true`) when supported, otherwise dual links
3. Pass symbol list to multi attach per function (single-symbol attach is still valid and keeps behavior predictable).
4. Ensure attach choice integrates with existing mode logic:
   - `--mode`
   - `(b)` / graph-triggered entry+exit
5. Extend graph attach path (`internal/bpfsnoop/bpf_tracing_graph.go`) so kernel-function graph targets also use multi attach when rule has `(m)`.
6. Keep non-`(m)` code path unchanged (`fentry/fexit/fsession`).

## 4) Add multi mode to flags

Goal: parse `(m)` and enforce the typed-argument requirement from spec.

Plan:

1. Extend `KfuncFlag` in `internal/bpfsnoop/flags_kfunc.go` with `multi bool`.
2. Parse `(m)` prefix in `parseKfuncFlag`.
3. Validation rule:
   - if `multi==true`, require both typed arg and arg name:
     - accepted: `(m)*:(struct sk_buff *)skb`
     - rejected: `(m)tcp_v4_connect`
4. Propagate `multi` through:
   - `progFlagImmInfo` (`internal/bpfsnoop/bpf_prog_flag.go`)
   - `KFunc.Flag` usage in kernel function discovery/tracing
   - graph-root handling (`-g`, `--fgraph-extra`)
5. Update help text in `internal/bpfsnoop/flags.go` and docs in `docs/how_to_build.md`.

## Verification (tests in `./t`)

Add concrete test cases under `./t` to validate spec and behavior:

1. Flag parsing / validation tests:
   - accept `(m)*:(struct sk_buff *)skb`
   - reject untyped `(m)` forms
2. Attach mode behavior tests:
   - entry-only `(m)` -> `kprobe.multi`
   - exit-only `(m)` -> `kretprobe.multi`
   - entry+exit `(m)` -> session when supported, fallback to dual multi links
3. Feature gating tests:
   - clear failure when `(m)` is requested without multi support
   - fallback behavior when session support is unavailable
4. Output parity smoke tests for `(m)` path:
   - `--filter-arg`, `--output-arg`
   - `--filter-pkt`, `--output-pkt`
   - `--output-lbr`, `--output-stack`, `--output-fgraph`
5. Regression tests:
   - non-`(m)` behavior remains unchanged
