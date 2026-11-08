---
name: k8s-pod-rca
description: >
  Performs deterministic root-cause analysis (RCA) for Kubernetes pods stuck in CrashLoopBackOff, OOMKilled, ImagePullBackOff, CreateContainerConfigError, Init:CrashLoopBackOff, or Pending/Evicted states. Use this skill when a DevOps Engineer, SRE, Platform Engineer, or Cloud Support Engineer needs to correlate pod status JSON, previous container logs, liveness/readiness/startup probe timing mismatches, cgroup memory/CPU limits, and namespace warning events into an exact root cause and a production-ready Kubernetes YAML manifest diff.
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

Upload or paste the generated `k8s-pod-snapshot.json` into the chat.

### Mode B: Manual `kubectl` Output Paste
If you cannot run the collector script, paste the output of the following three read-only commands:
1. `kubectl get pod <pod-name> -n <namespace> -o yaml` (specifically `spec.containers`, `status.containerStatuses`, and `status.conditions`)
2. `kubectl logs <pod-name> -n <namespace> --all-containers --previous --tail=150`
3. `kubectl get events -n <namespace> --field-selector involvedObject.name=<pod-name> --sort-by='.lastTimestamp'`

---

## Multi-Step Diagnostic & Execution Workflow

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

- **Collector Script:** [`scripts/collect-k8s-pod-triage.sh`](scripts/collect-k8s-pod-triage.sh) — Read-only Bash collector using `kubectl` to gather sanitized pod YAML/JSON, current and `--previous` container logs, namespace events, and resource metrics into a single JSON file.
- **Technical Reference:** [`references/k8s-exit-codes-and-probes.md`](references/k8s-exit-codes-and-probes.md) — Deep reference covering Linux signal math (`128 + N`), `OOMKilled` vs. Probe `137` disambiguation, JVM/Node/Python container memory sizing formulas, and probe anti-patterns.
- **Report Template:** [`assets/k8s-pod-rca-template.md`](assets/k8s-pod-rca-template.md) — Structured SRE Root Cause Analysis report with YAML manifest diff and Proof-of-Work summary.
