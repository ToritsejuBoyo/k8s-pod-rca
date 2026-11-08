# Kubernetes Container Exit Codes, Linux Signals & Probe Timing Reference

## 1. Container Exit Code & Signal Reference Matrix

In Linux and Kubernetes, when a container process is terminated by a signal `N`, its exit code is reported as **`128 + N`**.

| Exit Code | Signal / Name | K8s `reason` Field | Primary Root Causes | Diagnostic Verification |
| --- | --- | --- | --- | --- |
| `0` | None (`EXIT_SUCCESS`) | `Completed` | Process finished its main routine and exited cleanly. | If inside a `Deployment` (`restartPolicy: Always`), `kubelet` will restart a container that exits `0`, resulting in `CrashLoopBackOff`! Common when running a one-shot migration script inside a Deployment instead of a `Job`, or when a background daemon forks (`daemon off;` missing in Nginx). |
| `1` | Application Error | `Error` | Unhandled runtime exception, failed DB connection at boot, missing required env var, or bad config syntax. | Inspect `kubectl logs <pod> -c <container> --previous`. |
| `2` | Misuse of Shell Builtins | `Error` | Missing flag or syntax error in `/bin/sh -c "..."` inside `command` / `args`. | Check `spec.containers[].command` and `args` quoting. |
| `126` | Permission Denied | `ContainerCannotRun` | Entrypoint script is not executable (`chmod +x` missing) or filesystem is mounted `noexec`. | Verify `Dockerfile` permissions and `securityContext.runAsUser`. |
| `127` | Command Not Found | `ContainerCannotRun` | Binary specified in `command` does not exist in `$PATH`, or dynamically linked binary is missing `libc`/`musl` (e.g., running a glibc binary on `alpine` without `gcompat`). | Check base image (`alpine` vs `debian`/`distroless`) and `PATH`. |
| `128` | Invalid Exit Argument | `Error` | Application called `exit(-1)` or non-integer exit status. | Inspect application exit handler code. |
| `130` | `SIGINT` (`128 + 2`) | `Error` | Interrupted by `Ctrl+C` or manual interrupt signal. | Rare in automated clusters unless triggered via interactive attach. |
| `134` | `SIGABRT` (`128 + 6`) | `Error` | Native assertion failure, C/C++/Rust `abort()` / `panic!()`, or JVM native memory crash (`hs_err_pid.log`). | Check `--previous` logs for `SIGABRT`, `core dumped`, or `munmap_chunk(): invalid pointer`. |
| `137` | `SIGKILL` (`128 + 9`) | `OOMKilled` **OR** `Error` | **Immediate forced kill.** Caused by either (A) Linux kernel cgroup OOM killer, OR (B) `kubelet` killing a container that failed its Liveness/Startup Probe and did not stop within `terminationGracePeriodSeconds`. | **Must disambiguate!** Check `lastState.terminated.reason` and `kubectl get events`. See Section 2 below. |
| `139` | `SIGSEGV` (`128 + 11`) | `Error` | Segmentation fault (invalid memory reference, native C extension crash, or incompatible CPU instruction set). | Check node CPU architecture (`amd64` vs `arm64`) and native libraries. |
| `143` | `SIGTERM` (`128 + 15`) | `Error` | Graceful termination signal sent by `kubelet` due to Liveness/Startup Probe failure, Pod eviction, HPA scale-down, or RollingUpdate. | Check `kubectl get events` for `Killing` or `Unhealthy` events immediately preceding `finishedAt`. |
| `255` | Exit Status Out of Range | `Error` | Process returned `-1` or unhandled fatal error in wrapper script. | Check entrypoint wrapper script. |

---

## 2. Disambiguating the Two Causes of `Exit Code 137` (`SIGKILL`)

One of the most frequent SRE mistakes is assuming every `Exit Code 137` is an out-of-memory crash. Always compare these three fields:

| Diagnostic Field | Scenario A: Cgroup Memory Exhaustion (`OOMKilled`) | Scenario B: Liveness/Startup Probe Kill (`SIGKILL`) |
| --- | --- | --- |
| `lastState.terminated.exitCode` | `137` | `137` (or `143` if it exited cleanly on `SIGTERM`) |
| `lastState.terminated.reason` | **`OOMKilled`** | **`Error`** |
| Namespace Events (`kubectl get events`) | Kernel OOM event on node or container cgroup limit hit | `Warning Unhealthy: Liveness probe failed...` followed by `Normal Killing: Container X failed liveness probe, will be restarted` |
| Container Survival Duration (`finishedAt - startedAt`) | Varies with traffic load or memory leak rate | **Deterministic:** Equals `initialDelaySeconds + (periodSeconds * failureThreshold) + terminationGracePeriodSeconds` |

---

## 3. Runtime Memory Sizing Formulas (Preventing `OOMKilled`)

When a container's `resources.limits.memory` is set to `M_limit`, the Linux cgroup enforces a hard ceiling across **Heap + Off-Heap/Metaspace + Thread Stacks + Native Buffers + OS Page Cache**.

| Runtime | Classic Trap | Recommended Container Configuration |
| --- | --- | --- |
| **Java (JVM 11–21)** | Setting `-Xmx` equal to 100% of `limits.memory`, leaving zero headroom for Metaspace, Direct ByteBuffers, and GC threads (`OOMKilled` despite low JVM heap usage). | Set `JAVA_TOOL_OPTIONS="-XX:+UseContainerSupport -XX:InitialRAMPercentage=50.0 -XX:MaxRAMPercentage=75.0"` and ensure `limits.memory >= 512Mi`. |
| **Node.js (V8)** | V8 default heap limit (~1.5 GB–4 GB) exceeds small container limits (`512Mi`), or `--max-old-space-size` is set to 100% of container limit (ignoring Buffer/C++ RSS). | Set `NODE_OPTIONS="--max-old-space-size=<0.75 * limit_in_MB>"` (e.g., `384` for a `512Mi` limit). |
| **Python (Gunicorn / Uvicorn / Celery)** | Spawning too many prefork worker processes (`--workers 8`), where each worker loads ML models or pandas DataFrames into memory without copy-on-write sharing. | Reduce worker count (`2–4` per pod, scale horizontally via HPA instead) and set `--max-requests 1000 --max-requests-jitter 100` to recycle leaky workers gracefully. |
| **Go (`golang`)** | Prior to `GOMEMLIMIT` (Go 1.19+), the Go garbage collector only triggered at `GOGC=100` (2x live heap), causing sudden OOM kills near the container boundary. | Set `GOMEMLIMIT` to **80%–85%** of `resources.limits.memory` (e.g., `GOMEMLIMIT=850MiB` for a `1Gi` container limit). |

---

## 4. Kubernetes Probe Geometry Best Practices

1. **Never Use `livenessProbe` to Wait for Slow Cold Starts:**
   - Use **`startupProbe`** for slow initialization (migrations, JVM warm-up, cache loading). While `startupProbe` is running, `livenessProbe` and `readinessProbe` are disabled.
2. **Always Explicitly Set `timeoutSeconds`:**
   - The Kubernetes default for `timeoutSeconds` is **`1` second**. Always set `timeoutSeconds: 3` or `5` for HTTP probes to prevent transient GC pauses from triggering restarts.
3. **Never Check External Dependencies in `livenessProbe`:**
   - If your `livenessProbe` queries PostgreSQL or Redis and Redis experiences a 5-second network blip, Kubernetes will restart **all** of your application pods simultaneously, turning a minor dependency blip into a total cascading outage. Check external dependencies only in `readinessProbe` (or degraded health metrics), never in `livenessProbe`.
