---
name: k8s-pod-rca
description: >-
  Performs deterministic root-cause analysis (RCA) for Kubernetes pods stuck in CrashLoopBackOff,
  OOMKilled, ImagePullBackOff, CreateContainerConfigError, Init:CrashLoopBackOff, or
  Pending/Evicted states. Use this skill when a DevOps Engineer, SRE, Platform Engineer, or Cloud
  Support Engineer needs to correlate pod status JSON, previous container logs,
  liveness/readiness/startup probe timing mismatches, cgroup memory/CPU limits, and namespace
  warning events into an exact root cause and a production-ready Kubernetes YAML manifest diff.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
---

# Kubernetes CrashLoopBackOff & OOMKilled RCA Skill (`k8s-pod-rca`)

## Overview

When a Kubernetes workload enters `CrashLoopBackOff` or gets repeatedly terminated with `OOMKilled` (`Exit Code 137`), engineers frequently lose critical troubleshooting time running ad-hoc `kubectl` commands, misinterpreting current container logs instead of `--previous` termination logs, or increasing memory limits blindly without checking whether a Premature Liveness Probe (`SIGKILL` / `SIGTERM`) is actually killing a slow-starting JVM, Node.js, or Python process.

This skill pairs a zero-dependency, read-only Bash diagnostic collector (`scripts/collect-k8s-pod-triage.sh`) with a structured 5-step RCA workflow to pinpoint the exact failure layer (Scheduling, Image/Config, Init Container, Application Runtime, Cgroup OOM, or Probe Misconfiguration) and generate a validated YAML manifest patch.

---

## Operating Rules & Safety Guardrails

1. **Strictly Read-Only Cluster Inspection:**
   - Never execute mutating `kubectl` commands (`delete`, `patch`, `apply`, `scale`, `rollout restart`, `edit`, or `exec` destructive commands) automatically.
   - The bundled collector script (`scripts/collect-k8s-pod-triage.sh`) executes only read-only API calls (`get`, `describe`, `logs`, `top`) and strips `kubectl.kubernetes.io/last-applied-configuration` annotations and Secret data payloads.
2. **Secret & Environment Sanitization:**
   - Never output plaintext values from Kubernetes `Secret` objects, bearer tokens, database connection strings, or API keys found inside container `env` blocks or log stack traces. Always replace sensitive values with `[REDACTED_SECRET]`.
3. **QoS Class & Node Capacity Awareness:**
   - Before recommending an increase to `resources.limits.memory`, verify the relationship between `requests` and `limits` (Guaranteed vs. Burstable QoS class) and warn if removing or raising limits risks node-level memory pressure eviction (`NodeHasInsufficientMemory`).
4. **Distinguish Liveness Probe Kills from Cgroup OOMKills:**
   - Both a Linux kernel cgroup OOM kill and a failed liveness probe that ignores `SIGTERM` beyond `terminationGracePeriodSeconds` end with `SIGKILL` (`Exit Code 137`). Always verify `lastState.terminated.reason` (`OOMKilled` vs. `Error`) and namespace `Unhealthy` probe events before blaming memory exhaustion.

---

## Telemetry & Input Acquisition

### Mode A: Automated Read-Only Snapshot Script (Recommended)
Run the bundled Bash collector against the target namespace and pod:

```bash
bash ./scripts/collect-k8s-pod-triage.sh \
  --namespace production \
  --pod payments-api-7d9c8b6f4-x9k2m \
  --sanitize \
  --output ./k8s-pod-snapshot.json
```

On Windows hosts (PowerShell 5.1 / 7+), use the equivalent collector:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\collect-k8s-pod-triage.ps1 `
  -PodName payments-api-7d9c8b6f4-x9k2m `
  -Namespace production `
  -LogLines 150 `
  -OutputPath .\k8s-pod-snapshot.json
```

Note: the PowerShell collector has no `-Sanitize` switch. When using it, run the
analysis engine with its default sanitization enabled (Step 0) so masking still occurs
before any data leaves the host.

Upload or paste the generated `k8s-pod-snapshot.json` into the chat.

### Mode B: Manual `kubectl` Output Paste
If you cannot run the collector script, paste the output of the following three read-only commands:
1. `kubectl get pod <pod-name> -n <namespace> -o yaml` (specifically `spec.containers`, `status.containerStatuses`, and `status.conditions`)
2. `kubectl logs <pod-name> -n <namespace> --all-containers --previous --tail=150`
3. `kubectl get events -n <namespace> --field-selector involvedObject.name=<pod-name> --sort-by='.lastTimestamp'`

---

## Multi-Step Diagnostic & Execution Workflow

### Step 0: Run the Deterministic RCA Engine (Required First Step)
Always run the bundled analysis engine before reasoning manually. It implements the
full exit-code, probe-geometry, and cgroup correlation logic deterministically, so the
verdict is reproducible rather than inferred:

```bash
# Markdown RCA report (default)
python scripts/k8s_pod_rca.py -i ./k8s-pod-snapshot.json -f markdown

# Structured JSON for programmatic inspection
python scripts/k8s_pod_rca.py -i ./k8s-pod-snapshot.json -f json

# Ready-to-apply manifest patch only
python scripts/k8s_pod_rca.py -i ./k8s-pod-snapshot.json -f diff

# Every artifact at once into a directory
python scripts/k8s_pod_rca.py -i ./k8s-pod-snapshot.json -f all -o ./rca-out/
```

The engine accepts a collector bundle, raw `kubectl get pod -o json`, or a
`kubectl describe` text dump via `-i`, or on stdin when `-i` is omitted.
Client-side sanitization is **on by default**; pass `--no-sanitize` only when the
operator explicitly asks for unmasked output.

Use Steps 1-3 below to interpret and sanity-check the engine's findings. If the
engine reports `Diagnostic Confidence: Low`, fall back to manual analysis and say so
explicitly in the report.

### Step 1: Classify the Pod Phase & Container State Machine
Inspect `status.phase`, `status.conditions`, `status.initContainerStatuses`, and `status.containerStatuses`:
- **`Waiting` State Reasons:** `CrashLoopBackOff`, `ImagePullBackOff`, `ErrImagePull`, `CreateContainerConfigError`, `CreateContainerError`, `PodInitializing`.
- **`Terminated` State Inspection (`lastState.terminated` vs. `state.terminated`):**
  - Extract `exitCode`, `signal`, `reason` (`OOMKilled`, `Error`, `Completed`, `ContainerCannotRun`), `startedAt`, and `finishedAt`.
  - Calculate **Container Survival Duration** (`finishedAt - startedAt`). A survival duration of `< 2 seconds` points to an entrypoint/command error, missing shared library, or invalid config env var; a survival duration matching `initialDelaySeconds + (periodSeconds * failureThreshold)` points directly to a **Liveness Probe kill**.

### Step 2: Map Exit Codes & Signals to Root Cause
Cross-reference the observed exit code and termination reason using [`references/k8s-exit-codes-and-probes.md`](references/k8s-exit-codes-and-probes.md):
- **`Exit Code 137` (`SIGKILL` = `128 + 9`):**
  - **Case 1 (`reason: OOMKilled`):** The container exceeded `resources.limits.memory` (or node memory exhausted). Check if runtime heap settings (e.g., JVM `-Xmx` or Node `--max-old-space-size`) exceed 75%–80% of the container memory limit.
  - **Case 2 (`reason: Error` + Event `Killing` / `Unhealthy`):** Liveness or Startup probe failed repeatedly, `kubelet` sent `SIGTERM`, the process did not exit within `terminationGracePeriodSeconds`, and `kubelet` sent `SIGKILL`.
- **`Exit Code 143` (`SIGTERM` = `128 + 15`):** Graceful termination triggered by a failing Liveness Probe, Pod eviction, or node drain.
- **`Exit Code 1` / `2`:** Application-level unhandled exception, missing configuration file, database migration failure, or shell syntax error in `command`/`args`.
- **`Exit Code 126` / `127` / `128`:** Permission denied on entrypoint script (`chmod +x` missing), binary not found in `$PATH` or wrong base image architecture (`exec format error`), or invalid exit code invocation.

### Step 3: Audit Probe Geometry & Resource Requests/Limits
Perform a quantitative check on the pod spec:
1. **Startup vs. Liveness Probe Separation:** If the app takes up to `T_boot` seconds to initialize during cold starts or cache warming, ensure a `startupProbe` is configured with `failureThreshold * periodSeconds > T_boot * 1.5`, rather than inflating `livenessProbe.initialDelaySeconds`.
2. **Probe Timeout Trap:** In Kubernetes, `timeoutSeconds` defaults to `1` second! If an HTTP `/healthz` endpoint performs a synchronous database check or pauses during garbage collection for `1.2s`, the probe fails and triggers a restart cascade.
3. **Memory & CPU Sizing:** Compare `kubectl top pod` actual utilization against `resources.requests` and `resources.limits`. Check for CPU throttling (`cpu.cfs_quota_us`) slowing down application startup enough to trip liveness probes.

### Step 4: Generate the RCA Report & Manifest Patch
Populate [`assets/k8s-pod-rca-template.md`](assets/k8s-pod-rca-template.md) with:
- Exact root-cause classification and evidence table.
- A unified YAML diff (`Deployment` / `StatefulSet` / `DaemonSet`) fixing the probes, resource limits, runtime flags (`JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0"`), or security context.
- Safe rollout and verification commands (`kubectl diff -f`, `kubectl rollout status`).

### Step 5: Portfolio / Proof-of-Work Output Mode (`--generate-proof-of-work`)
When the user requests `--generate-proof-of-work` or a portfolio artifact:
1. Redact cluster URLs, internal container registry domains, namespace identifiers, and business-specific names.
2. Populate Section 6 of [`assets/k8s-pod-rca-template.md`](assets/k8s-pod-rca-template.md) to showcase a structured SRE case study demonstrating container lifecycle analysis, cgroup/probe correlation, and declarative YAML remediation.

---

## Bundled Resources

- **RCA Engine:** [`scripts/k8s_pod_rca.py`](scripts/k8s_pod_rca.py) — Deterministic analysis engine (stdlib only). Classifies pod phase, maps exit codes/signals, correlates probe geometry against cgroup limits, and emits markdown, JSON, manifest diff, prompt, HTML, or proof-of-work output. **Run this first (Step 0).**
- **Collector Script (PowerShell):** [`scripts/collect-k8s-pod-triage.ps1`](scripts/collect-k8s-pod-triage.ps1) — Read-only Windows collector producing the same snapshot bundle as the Bash collector.
- **Collector Script:** [`scripts/collect-k8s-pod-triage.sh`](scripts/collect-k8s-pod-triage.sh) — Read-only Bash collector using `kubectl` to gather sanitized pod YAML/JSON, current and `--previous` container logs, namespace events, and resource metrics into a single JSON file.
- **Technical Reference:** [`references/k8s-exit-codes-and-probes.md`](references/k8s-exit-codes-and-probes.md) — Deep reference covering Linux signal math (`128 + N`), `OOMKilled` vs. Probe `137` disambiguation, JVM/Node/Python container memory sizing formulas, and probe anti-patterns.
- **Report Template:** [`assets/k8s-pod-rca-template.md`](assets/k8s-pod-rca-template.md) — Structured SRE Root Cause Analysis report with YAML manifest diff and Proof-of-Work summary.

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.
