#!/usr/bin/env python3
"""Week 26: offline validation of the TracingPolicy files (no root, no Tetragon).

Checks for every policies/*.yaml:
  1. the file is valid YAML and is a cilium.io/v1alpha1 TracingPolicy
  2. metadata.name starts with "w26-" (so `tetra tracingpolicy list` shows lab policies clearly)
  3. every hook (kprobes / lsmhooks / tracepoints) has at least one selector with matchArgs,
     i.e. nothing is hooked globally without a filter
  4. SAFETY: every path filter is a lab-only path (suffix inside this folder's lab-files/)
     and every enforcement action (Sigkill / Override / Signal) sits in a selector that
     is restricted by such a lab-only path filter (matchArgs) or by matchBinaries whose
     values are all lab-files/ binaries.

Also checks that cilium/*.yaml (optional Cilium lab) is valid YAML.

Exit status 0 = all policies OK. Used by `make all` / `make test`.
"""
import glob
import os
import sys

try:
    import yaml
except ImportError:  # keep `make` usable on machines without PyYAML
    print("validate-policies: PyYAML not installed (apt install python3-yaml); skipping")
    sys.exit(0)

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_SUFFIX = "week26-ecosystem-tetragon-cilium/lab-files/"
PATH_TYPES = {"file", "path", "linux_binprm", "string"}
PATH_OPERATORS = {"Equal", "Prefix", "Postfix"}
ENFORCE_ACTIONS = {"Sigkill", "Override", "Signal"}
HOOK_SECTIONS = ("kprobes", "lsmhooks", "tracepoints", "uprobes")


def check_policy(path):
    errors = []
    with open(path) as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        return [f"{path}: not a YAML mapping"]
    if doc.get("apiVersion") != "cilium.io/v1alpha1" or doc.get("kind") != "TracingPolicy":
        errors.append("apiVersion/kind must be cilium.io/v1alpha1 TracingPolicy")
    name = (doc.get("metadata") or {}).get("name", "")
    if not name.startswith("w26-"):
        errors.append(f"metadata.name {name!r} must start with 'w26-'")

    spec = doc.get("spec") or {}
    hooks = [(sec, h) for sec in HOOK_SECTIONS for h in (spec.get(sec) or [])]
    if not hooks:
        errors.append("spec has no kprobes/lsmhooks/tracepoints")

    for sec, hook in hooks:
        hook_name = hook.get("call") or hook.get("hook") or hook.get("event") or "?"
        arg_types = {a["index"]: a.get("type") for a in hook.get("args") or []}
        selectors = hook.get("selectors") or []
        if not any(s.get("matchArgs") for s in selectors):
            errors.append(f"{sec}/{hook_name}: no matchArgs filter (would trace every call)")
        for i, sel in enumerate(selectors):
            lab_only = False
            for m in sel.get("matchArgs") or []:
                if arg_types.get(m.get("index")) in PATH_TYPES and m.get("operator") in PATH_OPERATORS:
                    vals = [str(v) for v in m.get("values") or []]
                    bad = [v for v in vals if LAB_SUFFIX not in v]
                    if bad:
                        errors.append(f"{sec}/{hook_name} selector {i}: non-lab path(s) {bad}")
                    elif vals:
                        lab_only = True
            # matchBinaries also restricts a selector, but only when every binary is a lab binary
            for m in sel.get("matchBinaries") or []:
                vals = [str(v) for v in m.get("values") or []]
                if m.get("operator") in ("In", "Prefix", "Postfix") and vals and all(
                    LAB_SUFFIX in v for v in vals
                ):
                    lab_only = True
            actions = {a.get("action") for a in sel.get("matchActions") or []}
            if actions & ENFORCE_ACTIONS and not lab_only:
                errors.append(
                    f"{sec}/{hook_name} selector {i}: {sorted(actions & ENFORCE_ACTIONS)} "
                    "is not restricted to a lab-files/ path"
                )
    return [f"{os.path.basename(path)}: {e}" for e in errors]


def main():
    files = sorted(glob.glob(os.path.join(HERE, "policies", "*.yaml")))
    if not files:
        print("validate-policies: no policies found")
        return 1
    all_errors = []
    for p in files:
        errs = check_policy(p)
        all_errors += errs
        print(f"  {'FAIL' if errs else 'ok  '}  policies/{os.path.basename(p)}")
    for p in sorted(glob.glob(os.path.join(HERE, "cilium", "*.yaml"))):
        try:
            with open(p) as f:
                list(yaml.safe_load_all(f))
            print(f"  ok    cilium/{os.path.basename(p)}")
        except yaml.YAMLError as exc:
            all_errors.append(f"cilium/{os.path.basename(p)}: {exc}")
            print(f"  FAIL  cilium/{os.path.basename(p)}")
    for e in all_errors:
        print(f"ERROR: {e}", file=sys.stderr)
    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
