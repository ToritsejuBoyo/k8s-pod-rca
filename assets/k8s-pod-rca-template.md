# Kubernetes Pod Failure Root Cause Analysis (RCA)

**Incident / Triage ID:** `K8S-RCA-{{DATE}}`
**Cluster / Namespace:** `{{NAMESPACE}}`
**Pod / Workload Name:** `{{POD_NAME}}` (Controlled by `{{CONTROLLER_KIND}}/{{CONTROLLER_NAME}}`)
**Observed Pod Status:** `{{OBSERVED_STATUS}}` (Restarts: `{{RESTART_COUNT}}`)

---

## 1. Executive Summary & Root Cause Verdict

- **Primary Failure Classification:** `{{FAILURE_CATEGORY}}` *(Cgroup OOMKilled / Liveness Probe Kill / Application Crash / Config & Secret Error / Scheduling & Eviction)*
- **Last Termination State:** Exit Code `{{EXIT_CODE}}` (`{{SIGNAL_NAME}}`) | Reason: `{{TERMINATION_REASON}}`
- **Container Survival Duration:** `{{SURVIVAL_DURATION_SECONDS}}` seconds (`{{STARTED_AT}}` to `{{FINISHED_AT}}`)
- **Root Cause Statement:**
  {{ROOT_CAUSE_SUMMARY}}

---

## 2. Diagnostic Evidence Correlation Matrix

| Telemetry Source | Observed Value / Log Evidence | Technical Interpretation |
| --- | --- | --- |
| **`status.containerStatuses[].lastState`** | `exitCode: {{EXIT_CODE}}, reason: {{TERMINATION_REASON}}` | {{INTERPRETATION_LAST_STATE}} |
| **Previous Container Logs (`--previous`)** | `{{PREVIOUS_LOG_EXCERPT}}` | {{INTERPRETATION_LOGS}} |
| **Namespace Events (`kubectl get events`)** | `{{EVENT_REASON}}: {{EVENT_MESSAGE}}` | {{INTERPRETATION_EVENTS}} |
| **Resources & QoS (`requests` / `limits`)** | CPU: `{{CPU_REQ}}/{{CPU_LIM}}`, Mem: `{{MEM_REQ}}/{{MEM_LIM}}` (QoS: `{{QOS_CLASS}}`) | {{INTERPRETATION_RESOURCES}} |
| **Probe Geometry (`startup` / `liveness`)** | `{{PROBE_CONFIG_SUMMARY}}` | {{INTERPRETATION_PROBES}} |

---

## 3. Declarative Kubernetes YAML Manifest Diff

Apply the following patch to your `{{CONTROLLER_KIND}}` manifest to resolve the root cause:

```diff
 apiVersion: apps/v1
 kind: {{CONTROLLER_KIND}}
 metadata:
   name: {{CONTROLLER_NAME}}
   namespace: {{NAMESPACE}}
 spec:
   template:
     spec:
       containers:
         - name: {{CONTAINER_NAME}}
+          env:
+            - name: {{RUNTIME_MEM_ENV_NAME}}
+              value: "{{RUNTIME_MEM_ENV_VALUE}}"
           resources:
             requests:
-              memory: "{{OLD_MEM_REQ}}"
+              memory: "{{NEW_MEM_REQ}}"
               cpu: "{{NEW_CPU_REQ}}"
             limits:
-              memory: "{{OLD_MEM_LIM}}"
+              memory: "{{NEW_MEM_LIM}}"
+          startupProbe:
+            httpGet:
+              path: {{HEALTH_PATH}}
+              port: {{HEALTH_PORT}}
+            periodSeconds: 5
+            failureThreshold: 30
+            timeoutSeconds: 3
           livenessProbe:
             httpGet:
               path: {{HEALTH_PATH}}
               port: {{HEALTH_PORT}}
-            initialDelaySeconds: {{OLD_INITIAL_DELAY}}
-            timeoutSeconds: 1
+            periodSeconds: 10
+            failureThreshold: 3
+            timeoutSeconds: 5
```

---

## 4. Safe Rollout & Verification Procedure

1. **Dry-Run & Diff Against Live Cluster State:**
   ```bash
   kubectl diff -f {{MANIFEST_FILE}} -n {{NAMESPACE}}
   ```
2. **Apply Manifest & Monitor Progressive Rollout:**
   ```bash
   kubectl apply -f {{MANIFEST_FILE}} -n {{NAMESPACE}}
   kubectl rollout status {{CONTROLLER_KIND}}/{{CONTROLLER_NAME}} -n {{NAMESPACE}} --timeout=180s
   ```
3. **Post-Deployment Stability Verification:**
   ```bash
   kubectl get pods -n {{NAMESPACE}} -l app={{APP_LABEL}} -w
   kubectl top pods -n {{NAMESPACE}} -l app={{APP_LABEL}} --containers
   ```
4. **Immediate Rollback Command (If Regression Occurs):**
   ```bash
   kubectl rollout undo {{CONTROLLER_KIND}}/{{CONTROLLER_NAME}} -n {{NAMESPACE}}
   ```

---

## 5. Verified Proof-of-Work Case Study (`--generate-proof-of-work`)

> *Sanitized technical case study for SRE / DevOps engineering portfolio documentation.*

- **Incident Context:** Production Kubernetes workload (`{{SANITIZED_WORKLOAD_NAME}}`) experienced recurring `{{OBSERVED_STATUS}}` restarts (Exit Code `{{EXIT_CODE}}`), degrading service availability during peak traffic / deployment rollouts.
- **Triage & Telemetry Analysis:** Captured read-only pod state, `--previous` container logs, and namespace events using `collect-k8s-pod-triage.sh`. Calculated container survival duration (`{{SURVIVAL_DURATION_SECONDS}}s`) and correlated `lastState.terminated.reason` (`{{TERMINATION_REASON}}`) against probe timing and cgroup resource boundaries.
- **Root Cause Identified:** {{SANITIZED_ROOT_CAUSE}}
- **Declarative Fix:** Patched workload resource requests/limits, aligned runtime memory ceiling flags (`{{RUNTIME_MEM_ENV_NAME}}`), and decoupled cold-start initialization into a dedicated `startupProbe` with explicit `timeoutSeconds`.
- **Measurable Outcome:** Eliminated pod restart loops (`0` restarts over 7-day post-change observation window) and improved rollout reliability.
