// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/mathx"
)

func (t *bpfTracing) traceFuncsMulti(errg *errgroup.Group, reusedMaps map[string]*ebpf.Map, fn *KFunc, bothEntryExit bool) error {
	if !hasKprobeMulti {
		return fmt.Errorf("kprobe.multi is not supported for function %s", fn.Func.Name)
	}

	kmultiSpec, err := bpf.LoadKmulti()
	if err != nil {
		return fmt.Errorf("failed to load kmulti bpf spec: %w", err)
	}

	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get possible cpu count for kmulti spec: %w", err)
	}
	if err := kmultiSpec.Variables["CPU_MASK"].Set(uint32(mathx.Mask(numCPU))); err != nil {
		return fmt.Errorf("failed to set CPU_MASK for kmulti spec: %w", err)
	}

	if err := kmultiSpec.Variables["PID"].Set(uint32(os.Getpid())); err != nil {
		return fmt.Errorf("failed to set PID for kmulti spec: %w", err)
	}

	if bothEntryExit {
		if hasKprobeSession {
			errg.Go(func() error {
				return t.traceFuncMulti(kmultiSpec, reusedMaps, fn, true, true, true, fn.Flag.stack)
			})
			return nil
		}

		errg.Go(func() error {
			return t.traceFuncMulti(kmultiSpec, reusedMaps, fn, true, false, false, false)
		})
		errg.Go(func() error {
			return t.traceFuncMulti(kmultiSpec, reusedMaps, fn, true, true, false, fn.Flag.stack)
		})
		return nil
	}

	errg.Go(func() error {
		return t.traceFuncMulti(kmultiSpec, reusedMaps, fn, false, hasModeExit(), false, fn.Flag.stack)
	})
	return nil
}

func (t *bpfTracing) traceFuncMulti(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn *KFunc, bothEntryExit, isExit, session, stack bool) error {
	spec = spec.Copy()

	tracingFuncName := "bpfsnoop_kmulti"
	if bothEntryExit && session {
		tracingFuncName = "bpfsnoop_ksession"
		delete(spec.Programs, "bpfsnoop_kmulti")
	} else {
		delete(spec.Programs, "bpfsnoop_ksession")
	}

	traceeName := fn.Func.Name
	progSpec := spec.Programs[tracingFuncName]
	funcProto := fn.Func.Type.(*btf.FuncProto)
	params := funcProto.Params
	fn.Pkt = t.injectPktOutput(fn.Flag.pkt, progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, fn.Btf, traceeName); err != nil {
		return err
	}
	args, argDataSize, err := t.injectArgOutput(progSpec, params, fn.Btf, traceeName)
	if err != nil {
		return err
	}
	fn.Args = args
	fn.Data = argDataSize

	withRet := isExit
	fnArgsBufSize, err := injectOutputFuncArgs(progSpec, fn.Prms, fn.Ret, withRet)
	if err != nil {
		return fmt.Errorf("failed to inject output func args: %w", err)
	}
	if isExit {
		fn.Exit = fnArgsBufSize
	} else {
		fn.Ent = fnArgsBufSize
	}

	if err := setBpfsnoopConfig(spec, fn.Ksym.addr, len(fn.Prms), fnArgsBufSize,
		argDataSize, fn.Flag.lbr, stack, fn.Pkt, bothEntryExit, withRet, session); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if ignoreFuncTraceVerifierErr(err, traceeName) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing %s in multi mode: %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)

	opts := link.KprobeMultiOptions{
		Symbols: []string{traceeName},
		Session: bothEntryExit && session,
	}

	var l link.Link
	if isExit && !opts.Session {
		l, err = link.KretprobeMulti(prog, opts)
	} else {
		l, err = link.KprobeMulti(prog, opts)
	}
	if err != nil {
		_ = prog.Close()
		if ignoreFuncTraceErr(err, traceeName) {
			return nil
		}
		return fmt.Errorf("failed to attach tracing in multi mode: %w", err)
	}

	verboseLogIf(opts.Session, "Tracing(ksession) kernel function %s", traceeName)
	verboseLogIf(!opts.Session && isExit, "Tracing(kretprobe.multi) kernel function %s", traceeName)
	verboseLogIf(!opts.Session && !isExit, "Tracing(kprobe.multi) kernel function %s", traceeName)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.kfns = append(t.kfns, tracingFunc{
		l: l,
		p: prog,
	})
	t.llock.Unlock()

	return nil
}
