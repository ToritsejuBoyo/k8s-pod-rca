#!/usr/bin/env python3
"""
Kubernetes CrashLoopBackOff & OOMKilled RCA Engine (k8s-pod-rca)

Autonomous, deterministic, client-side diagnostic engine that ingests
Kubernetes pod snapshots, decodes container exit codes, cgroup limits,
probe timings, and lifecycle events, and synthesizes a production-ready
K8s YAML manifest diff and SRE Root Cause Analysis report.

Zero external dependencies - Python standard library only.
Strict zero-emoji enterprise tone (Rule 7).
Client-side PII sanitization (Rule 4).
"""

import argparse
import dataclasses
from dataclasses import dataclass, field
import datetime
import difflib
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Shared residual sanitization pass (vendored: scripts/sanitizer.py).
# Runs last, after this skill's domain-specific masking, so that every skill in
# the library enforces an identical credential/PII floor. See
# tests/sanitizer_conformance_test.py for the contract this must satisfy.
# ---------------------------------------------------------------------------
try:
    from sanitizer import residual_scrub as _residual_scrub
except ImportError:  # pragma: no cover - direct execution from another cwd
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from sanitizer import residual_scrub as _residual_scrub



# ----------------------------------------------------------------------
# Client-Side Data Sanitization (Rule 4 & Rule 7)
# ----------------------------------------------------------------------

class Sanitizer:
    """
    Deterministic client-side sanitization engine for Kubernetes telemetry.
    Scrubs internal IP addresses, cluster FQDNs, node hostnames, container IDs,
    service account tokens, cloud credentials, environment secrets, and emojis.
    """

    # Bounded RFC 5321 regex to avoid polynomial ReDoS backtracking
    EMAIL_PATTERN = re.compile(
        r"(?<![\w._%+-/])[\w._%+-]{1,64}@[\w.-]{1,255}\.[\w-]{2,24}\b",
        re.UNICODE
    )

    # Standard GUID / UUID
    GUID_PATTERN = re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    )

    # IPv4 addresses
    IPV4_PATTERN = re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
    )

    # IPv6 addresses (full, compressed, and zone-indexed)
    IPV6_PATTERN = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:%[a-zA-Z0-9_.-]+)?\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}(?:%[a-zA-Z0-9_.-]+)?\b|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?:%[a-zA-Z0-9_.-]+)?\b|"
        r"\bfe80::[0-9a-fA-F:]*(?:%[a-zA-Z0-9_.-]+)?\b"
    )

    # Internal Kubernetes cluster DNS domains (*.svc.cluster.local)
    CLUSTER_DNS_PATTERN = re.compile(
        r"\b[a-zA-Z0-9_-]{1,63}(?:\.[a-zA-Z0-9_-]{1,63})*\.svc\.cluster\.local\b",
        re.IGNORECASE
    )

    # Cloud container registries (bounded RFC labels to eliminate ReDoS backtracking)
    REGISTRY_PATTERN = re.compile(
        r"\b(?:\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com|[a-zA-Z0-9]{3,50}\.azurecr\.io|(?:(?:us|eu|asia)\.)?gcr\.io|[a-zA-Z0-9_.-]{1,63}\.pkg\.dev|harbor\.[a-zA-Z0-9_.-]{1,63})\b",
        re.IGNORECASE
    )

    # Kubernetes Node hostnames (bounded labels to prevent ReDoS backtracking)
    NODE_HOSTNAME_PATTERN = re.compile(
        r"(?<![a-zA-Z0-9_-])(?:ip-(?:\d{1,3}-){3}\d{1,3}|aks-[a-z0-9_-]{1,63}|gke-[a-z0-9_-]{1,63}|worker-[a-z0-9_-]{1,63}|node-[a-z0-9_-]{1,63}|k8s-node-[a-z0-9_-]{1,63})(?:\.[a-zA-Z0-9_.-]{1,63})?(?![a-zA-Z0-9_-])",
        re.IGNORECASE
    )

    # Container runtime IDs (containerd, docker, cri-o)
    CONTAINER_ID_PATTERN = re.compile(
        r"\b(?:containerd|docker|cri-o)://[0-9a-fA-F]{64}\b"
    )

    # Kubernetes ServiceAccount JWT tokens and Bearer tokens
    TOKEN_PATTERNS = [
        re.compile(r"\beyJhbGciOi[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS Access Key ID
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),  # GitHub Token
        re.compile(r"(?i)(?:password|passwd|pwd|secret[_-]?key|secret|token|api[_-]?(?:key|token)|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"]?([^\s'\",;]{1,256})['\"]?"),
        re.compile(r"\b(?:bearer\s+[a-zA-Z0-9_\-\.]{20,512})\b", re.IGNORECASE),
    ]

    # Rule 7 Enterprise compliance: scrub casual or user-submitted emojis
    EMOJI_PATTERN = re.compile(
        r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
    )

    def __init__(self, salt: str = "k8s-rca-salt") -> None:
        self.salt = salt
        self._ip_map: Dict[str, str] = {}
        self._node_map: Dict[str, str] = {}
        self._ip_counter = 1
        self._node_counter = 1

    def _mask_ipv4(self, match: re.Match) -> str:
        ip = match.group(0)
        # Preserve loopback or RFC 5737 documentation test IPs
        if ip.startswith("127.") or ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113."):
            return ip
        if ip in self._ip_map:
            return self._ip_map[ip]
        mapped = f"192.0.2.{self._ip_counter % 250 + 1}"
        self._ip_counter += 1
        self._ip_map[ip] = mapped
        return mapped

    def _mask_node(self, match: re.Match) -> str:
        node = match.group(0)
        if node.lower().startswith("node-") and node.lower().endswith(".internal"):
            return node
        if node in self._node_map:
            return self._node_map[node]
        mapped = f"node-{self._node_counter:02d}.internal"
        self._node_counter += 1
        self._node_map[node] = mapped
        return mapped

    def scrub(self, text: str) -> str:
        """
        Applies full data sanitization pipeline to the provided Kubernetes text.
        """
        if not text:
            return ""

        # 0. Strip zero-width characters and invisible formatting
        text = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]", "", text)

        # 1. Neutralize dangerous script execution schemes
        text = re.sub(r"(?i)\bjavascript\s*:", "[BLOCKED_SCRIPT]:", text)

        # 2. Scrub Container Runtime IDs
        text = self.CONTAINER_ID_PATTERN.sub("containerd://[REDACTED_CONTAINER_ID]", text)

        # 3. Scrub GUIDs early
        text = self.GUID_PATTERN.sub("00000000-0000-4000-a000-000000000000", text)

        # 4. Scrub credentials, JWTs, and cloud API keys
        for pattern in self.TOKEN_PATTERNS:
            text = pattern.sub("[REDACTED_SECRET]", text)

        # 5. Scrub emails
        text = self.EMAIL_PATTERN.sub("user-masked@example.local", text)

        # 6. Scrub registry URLs
        text = self.REGISTRY_PATTERN.sub("registry.example.local", text)

        # 7. Scrub cluster FQDNs (*.svc.cluster.local)
        text = self.CLUSTER_DNS_PATTERN.sub("service.namespace.svc.example.local", text)

        # 8. Scrub Node Hostnames
        text = self.NODE_HOSTNAME_PATTERN.sub(self._mask_node, text)

        # 9. Scrub IPv4 addresses
        text = self.IPV4_PATTERN.sub(self._mask_ipv4, text)

        # 10. Scrub IPv6 addresses
        text = self.IPV6_PATTERN.sub("2001:db8::1", text)

        # 11. Scrub any residual emoji characters to enforce Rule 7 compliance
        text = self.EMOJI_PATTERN.sub("", text)

        text = _residual_scrub(text)
        return text


# ----------------------------------------------------------------------
# Kubernetes Data Structures
# ----------------------------------------------------------------------

@dataclass
class ContainerStatus:
    name: str = "main"
    ready: bool = False
    restart_count: int = 0
    state_reason: str = ""
    state_message: str = ""
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    started_at: str = ""
    finished_at: str = ""
    is_oom_killed: bool = False
    survival_seconds: Optional[float] = None


@dataclass
class ProbeConfig:
    probe_type: str = "liveness"  # liveness, readiness, startup
    path: str = ""
    port: Any = None
    initial_delay_seconds: int = 0
    period_seconds: int = 10
    timeout_seconds: int = 1
    failure_threshold: int = 3
    success_threshold: int = 1


@dataclass
class ResourceConfig:
    cpu_request: str = ""
    cpu_limit: str = ""
    memory_request: str = ""
    memory_limit: str = ""


@dataclass
class PodSnapshot:
    pod_name: str = "synthetic-pod"
    namespace: str = "default"
    phase: str = "Running"
    qos_class: str = "Burstable"
    node_name: str = "node-01.internal"
    containers: List[ContainerStatus] = field(default_factory=list)
    init_containers: List[ContainerStatus] = field(default_factory=list)
    probes: Dict[str, Dict[str, ProbeConfig]] = field(default_factory=dict)
    resources: Dict[str, ResourceConfig] = field(default_factory=dict)
    events: List[str] = field(default_factory=list)
    previous_logs: Dict[str, str] = field(default_factory=dict)
    current_logs: Dict[str, str] = field(default_factory=dict)
    raw_manifest: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RCAResult:
    category: str = "CrashLoopBackOff"  # OOMKilled, LivenessProbeTimeout, MissingSecret, CommandNotFound, PermissionDenied, Segfault, Evicted
    confidence: str = "High"  # High, Medium, Low
    exit_code: Optional[int] = None
    survival_seconds: Optional[float] = None
    faulting_container: str = "main"
    immediate_cause: str = ""
    root_cause: str = ""
    evidence: List[str] = field(default_factory=list)
    timeline: List[str] = field(default_factory=list)
    manifest_patch: str = ""
    verification_commands: List[str] = field(default_factory=list)
    target_controller: str = "Deployment"


# ----------------------------------------------------------------------
# Telemetry Parser
# ----------------------------------------------------------------------

class PodSnapshotParser:
    """
    Ingests Kubernetes telemetry across diverse formats:
    - Structured JSON snapshot (from collect-k8s-pod-triage.sh/.ps1)
    - Raw kubectl get pod -o json
    - Raw kubectl describe pod text output
    - Plain text incident transcripts combining manifests, logs, and events.
    """

    def __init__(self, sanitizer: Optional[Sanitizer] = None) -> None:
        self.sanitizer = sanitizer or Sanitizer()

    def parse(self, raw_content: str) -> PodSnapshot:
        content = raw_content.replace("\r\n", "\n").replace("\r", "\n").strip()
        if not content:
            return PodSnapshot(pod_name="empty-input", phase="Unknown")

        # Strip UTF-8 BOM if present
        if content.startswith("\ufeff"):
            content = content[1:].strip()

        # Strip ANSI escape sequences if terminal transcripts are passed
        content = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", content)

        # Attempt structured JSON parsing
        if content.startswith("{") and content.endswith("}"):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    # Check for collector snapshot schema
                    if "pod_spec_and_status" in data or "pod" in data:
                        return self._parse_collector_snapshot(data)
                    # Check for direct kubectl get pod -o json or generic pod dictionary
                    elif data.get("kind") == "Pod" or "status" in data or "spec" in data:
                        return self._parse_k8s_pod_json(data)
            except (json.JSONDecodeError, RecursionError):
                pass

        # Fall back to raw text / kubectl describe parser
        return self._parse_describe_or_text(content)

    def _parse_collector_snapshot(self, data: Dict[str, Any]) -> PodSnapshot:
        pod_data = data.get("pod_spec_and_status", data.get("pod", {}))
        snapshot = self._parse_k8s_pod_json(pod_data)

        # Extract namespace events if provided in snapshot bundle
        events_list = data.get("events", [])
        if isinstance(events_list, list):
            for ev in events_list:
                if isinstance(ev, str):
                    snapshot.events.append(ev.strip())
                elif isinstance(ev, dict):
                    msg = ev.get("message", ev.get("note", ""))
                    reason = ev.get("reason", "")
                    typ = ev.get("type", "Normal")
                    snapshot.events.append(f"{typ} {reason}: {msg}")

        # Extract previous container logs
        prev_logs = data.get("previous_logs", {})
        if isinstance(prev_logs, dict):
            for c_name, log_text in prev_logs.items():
                if isinstance(log_text, str):
                    snapshot.previous_logs[c_name] = log_text

        # Extract current container logs
        cur_logs = data.get("current_logs", {})
        if isinstance(cur_logs, dict):
            for c_name, log_text in cur_logs.items():
                if isinstance(log_text, str):
                    snapshot.current_logs[c_name] = log_text

        return snapshot

    def _parse_k8s_pod_json(self, data: Dict[str, Any]) -> PodSnapshot:
        snapshot = PodSnapshot()
        snapshot.raw_manifest = data

        meta = data.get("metadata", {})
        snapshot.pod_name = str(meta.get("name", "synthetic-pod"))
        snapshot.namespace = str(meta.get("namespace", "default"))

        status = data.get("status", {})
        snapshot.phase = str(status.get("phase", "Running"))
        snapshot.qos_class = str(status.get("qosClass", "Burstable"))
        snapshot.node_name = str(data.get("spec", {}).get("nodeName", status.get("hostIP", "node-01.internal")))

        spec = data.get("spec", {})
        containers_spec = spec.get("containers", [])
        for c in containers_spec:
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "main")
            # Parse resource requests and limits
            res = c.get("resources", {})
            reqs = res.get("requests", {})
            limits = res.get("limits", {})
            snapshot.resources[c_name] = ResourceConfig(
                cpu_request=str(reqs.get("cpu", "")),
                cpu_limit=str(limits.get("cpu", "")),
                memory_request=str(reqs.get("memory", "")),
                memory_limit=str(limits.get("memory", ""))
            )

            # Parse probes
            c_probes: Dict[str, ProbeConfig] = {}
            for p_type in ["livenessProbe", "readinessProbe", "startupProbe"]:
                if p_type in c and isinstance(c[p_type], dict):
                    p_obj = c[p_type]
                    http_get = p_obj.get("httpGet", {})
                    path = http_get.get("path", "")
                    port = http_get.get("port", p_obj.get("tcpSocket", {}).get("port", None))
                    c_probes[p_type.replace("Probe", "")] = ProbeConfig(
                        probe_type=p_type.replace("Probe", ""),
                        path=path,
                        port=port,
                        initial_delay_seconds=int(p_obj.get("initialDelaySeconds", 0)),
                        period_seconds=int(p_obj.get("periodSeconds", 10)),
                        timeout_seconds=int(p_obj.get("timeoutSeconds", 1)),
                        failure_threshold=int(p_obj.get("failureThreshold", 3)),
                        success_threshold=int(p_obj.get("successThreshold", 1))
                    )
            snapshot.probes[c_name] = c_probes

        # Parse container status and termination reasons
        c_statuses = status.get("containerStatuses", [])
        for cs in c_statuses:
            if not isinstance(cs, dict):
                continue
            c_stat = self._extract_container_status(cs)
            snapshot.containers.append(c_stat)

        # Parse init container status
        init_statuses = status.get("initContainerStatuses", [])
        for ics in init_statuses:
            if not isinstance(ics, dict):
                continue
            c_stat = self._extract_container_status(ics)
            snapshot.init_containers.append(c_stat)

        # Parse ephemeral container statuses (K8s 1.25+ kubectl debug containers)
        ephemeral_statuses = status.get("ephemeralContainerStatuses", [])
        if isinstance(ephemeral_statuses, list):
            for ecs in ephemeral_statuses:
                if not isinstance(ecs, dict):
                    continue
                c_stat = self._extract_container_status(ecs)
                snapshot.containers.append(c_stat)

        return snapshot

    def _extract_container_status(self, cs: Dict[str, Any]) -> ContainerStatus:
        c_stat = ContainerStatus()
        c_stat.name = str(cs.get("name", "main"))
        c_stat.ready = bool(cs.get("ready", False))
        c_stat.restart_count = int(cs.get("restartCount", 0))

        state = cs.get("state", {})
        last_state = cs.get("lastState", {})

        # Inspect current state
        if "waiting" in state and isinstance(state["waiting"], dict):
            c_stat.state_reason = state["waiting"].get("reason", "Waiting")
            c_stat.state_message = state["waiting"].get("message", "")
        elif "terminated" in state and isinstance(state["terminated"], dict):
            term = state["terminated"]
            c_stat.state_reason = term.get("reason", "Terminated")
            c_stat.state_message = term.get("message", "")
            c_stat.exit_code = term.get("exitCode")
            c_stat.signal = term.get("signal")
            c_stat.started_at = term.get("startedAt", "")
            c_stat.finished_at = term.get("finishedAt", "")
            if c_stat.state_reason == "OOMKilled" or c_stat.exit_code == 137:
                c_stat.is_oom_killed = (c_stat.state_reason == "OOMKilled")

        # Inspect last state if current is waiting (classic CrashLoopBackOff)
        if "terminated" in last_state and isinstance(last_state["terminated"], dict):
            last_term = last_state["terminated"]
            if c_stat.exit_code is None:
                c_stat.exit_code = last_term.get("exitCode")
            if not c_stat.state_reason or c_stat.state_reason == "CrashLoopBackOff":
                c_stat.state_reason = last_term.get("reason", c_stat.state_reason)
            c_stat.signal = last_term.get("signal")
            c_stat.started_at = last_term.get("startedAt", "")
            c_stat.finished_at = last_term.get("finishedAt", "")
            if last_term.get("reason") == "OOMKilled":
                c_stat.is_oom_killed = True

        # Calculate container survival duration
        if c_stat.started_at and c_stat.finished_at:
            start_dt = self._parse_timestamp(c_stat.started_at)
            finish_dt = self._parse_timestamp(c_stat.finished_at)
            if start_dt and finish_dt:
                c_stat.survival_seconds = max(0.0, (finish_dt - start_dt).total_seconds())

        return c_stat

    def _parse_timestamp(self, ts: str) -> Optional[datetime.datetime]:
        """
        Parses ISO 8601, RFC 3339, nanoseconds, or RFC 2822 timestamps safely.
        """
        if not ts or not isinstance(ts, str):
            return None
        clean = ts.strip()
        # Truncate nanoseconds to microseconds (6 digits) if needed
        clean = re.sub(r"(\.\d{6})\d+", r"\1", clean)
        try:
            iso_str = clean.replace("Z", "+00:00")
            return datetime.datetime.fromisoformat(iso_str)
        except (ValueError, TypeError):
            pass
        try:
            import email.utils
            return email.utils.parsedate_to_datetime(clean)
        except Exception:
            pass
        return None

    def _parse_describe_or_text(self, text: str) -> PodSnapshot:
        snapshot = PodSnapshot()
        lines = text.splitlines()

        c_name = "main"
        exit_code = None
        term_reason = ""
        restarts = 0
        started_at = ""
        finished_at = ""
        events: List[str] = []
        log_lines: List[str] = []

        is_event_section = False
        is_log_section = False
        in_containers_section = False

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            lower_line = line_str.lower()

            if lower_line.startswith("name:") and (not snapshot.pod_name or snapshot.pod_name == "synthetic-pod"):
                snapshot.pod_name = line_str.split(":", 1)[1].strip()
            elif lower_line.startswith("namespace:") and snapshot.namespace == "default":
                snapshot.namespace = line_str.split(":", 1)[1].strip()
            elif lower_line.startswith("status:") or lower_line.startswith("phase:"):
                snapshot.phase = line_str.split(":", 1)[1].strip()
            elif lower_line.startswith("node:"):
                snapshot.node_name = line_str.split(":", 1)[1].strip().split("/")[0]

            # Detect sections
            if lower_line.startswith("containers:"):
                in_containers_section = True
                continue
            elif "events:" in lower_line or lower_line.startswith("events:"):
                is_event_section = True
                is_log_section = False
                in_containers_section = False
                continue
            elif any(lower_line.startswith(p) for p in ["conditions:", "volumes:", "tolerations:", "qos class:", "node-selectors:"]):
                in_containers_section = False
                continue
            elif "logs:" in lower_line or "previous log:" in lower_line or lower_line.startswith("--- logs"):
                is_log_section = True
                is_event_section = False
                in_containers_section = False
                continue

            if in_containers_section and line_str.endswith(":") and not any(lower_line.startswith(p) for p in ["limits:", "requests:", "liveness:", "readiness:", "startup:", "environment:", "mounts:", "args:", "command:", "state:", "last state:"]):
                candidate = line_str[:-1].strip()
                if " " not in candidate and len(candidate) > 1 and not candidate.startswith("-"):
                    c_name = candidate

            if is_event_section:
                events.append(line_str)
            elif is_log_section:
                log_lines.append(line_str)

            # Detect exit codes and reasons in text
            exit_m = re.search(r"exit\s*code:?\s*(\d+)", line_str, re.IGNORECASE)
            if exit_m:
                exit_code = int(exit_m.group(1))

            if lower_line.startswith("started:"):
                started_at = line_str.split(":", 1)[1].strip()
            elif lower_line.startswith("finished:"):
                finished_at = line_str.split(":", 1)[1].strip()

            if "oomkilled" in lower_line:
                term_reason = "OOMKilled"
            elif "crashloopbackoff" in lower_line:
                if not term_reason:
                    term_reason = "CrashLoopBackOff"
            elif "createcontainerconfigerror" in lower_line:
                term_reason = "CreateContainerConfigError"
            elif "imagepullbackoff" in lower_line:
                term_reason = "ImagePullBackOff"

            restart_m = re.search(r"restart\s*count:?\s*(\d+)", line_str, re.IGNORECASE)
            if restart_m:
                restarts = int(restart_m.group(1))

        # Check for Liveness probe configuration in text
        if "liveness:" in text.lower():
            p_m = re.search(r"delay=(\d+)s.*timeout=(\d+)s.*period=(\d+)s.*#failure=(\d+)", text, re.IGNORECASE)
            if p_m:
                snapshot.probes[c_name] = {
                    "liveness": ProbeConfig(
                        probe_type="liveness",
                        initial_delay_seconds=int(p_m.group(1)),
                        timeout_seconds=int(p_m.group(2)),
                        period_seconds=int(p_m.group(3)),
                        failure_threshold=int(p_m.group(4))
                    )
                }

        start_dt = self._parse_timestamp(started_at)
        finish_dt = self._parse_timestamp(finished_at)
        survival_seconds = None
        if start_dt and finish_dt:
            survival_seconds = max(0.0, (finish_dt - start_dt).total_seconds())

        c_stat = ContainerStatus(
            name=c_name,
            exit_code=exit_code,
            state_reason=term_reason or ("OOMKilled" if exit_code == 137 and any(w in text.lower() for w in ["oom", "out of memory", "signal 9", "sigkill"]) else "Error"),
            restart_count=restarts,
            started_at=started_at,
            finished_at=finished_at,
            survival_seconds=survival_seconds,
            is_oom_killed=(term_reason == "OOMKilled" or (exit_code == 137 and any(w in text.lower() for w in ["oom", "out of memory", "signal 9", "sigkill"])))
        )
        snapshot.containers.append(c_stat)
        snapshot.events = events
        if log_lines:
            snapshot.previous_logs[c_name] = "\n".join(log_lines)

        return snapshot


# ----------------------------------------------------------------------
# Root Cause Analysis & Diagnostic Engine
# ----------------------------------------------------------------------

class K8sRCAEngine:
    """
    Evaluates PodSnapshot telemetry and derives the exact root cause,
    manifest remediation diff, and verification runbook.
    """

    def __init__(self, sanitizer: Optional[Sanitizer] = None) -> None:
        self.sanitizer = sanitizer or Sanitizer()

    def analyze(self, snapshot: PodSnapshot) -> RCAResult:
        # Determine faulting container
        faulting_container = "main"
        primary_status: Optional[ContainerStatus] = None

        # Check init containers first (if an init container failed, it blocks the entire pod)
        if snapshot.init_containers:
            for ics in snapshot.init_containers:
                if (ics.exit_code is not None and ics.exit_code != 0) or ics.state_reason in ["Error", "CrashLoopBackOff"]:
                    primary_status = ics
                    faulting_container = ics.name
                    break

        if not primary_status and snapshot.containers:
            # Pick container with non-zero exit code or waiting state
            for cs in snapshot.containers:
                if cs.exit_code is not None and cs.exit_code != 0:
                    primary_status = cs
                    faulting_container = cs.name
                    break
                elif cs.state_reason in ["CrashLoopBackOff", "OOMKilled", "CreateContainerConfigError", "ImagePullBackOff", "ErrImagePull"]:
                    primary_status = cs
                    faulting_container = cs.name
                    break
            if not primary_status:
                primary_status = snapshot.containers[0]
                faulting_container = primary_status.name
        elif not primary_status:
            primary_status = ContainerStatus()

        result = RCAResult(
            faulting_container=faulting_container,
            exit_code=primary_status.exit_code,
            survival_seconds=primary_status.survival_seconds
        )

        all_text = f"{snapshot.phase} {primary_status.state_reason} {primary_status.state_message} " \
                   f"{' '.join(snapshot.events)} {' '.join(snapshot.previous_logs.values())} " \
                   f"{' '.join(snapshot.current_logs.values())}"
        lower_text = all_text.lower()

        # Check for Scheduling failure (Pending state with unschedulable events and no container config errors)
        if any("failedscheduling" in ev.lower() or "insufficient" in ev.lower() or "unschedulable" in ev.lower() for ev in snapshot.events) and \
           not any(cs.state_reason in ["CreateContainerConfigError", "CreateContainerError"] for cs in snapshot.containers):
            self._diagnose_scheduling_failure(snapshot, result)
            return result

        # 1. Check for OOMKilled (Exit Code 137 + cgroup kill)
        if primary_status.is_oom_killed or (primary_status.exit_code == 137 and any(w in lower_text for w in ["oom", "out of memory", "killed process", "signal 9", "sigkill"])):
            self._diagnose_oomkilled(snapshot, primary_status, result)
            return result

        # 2. Check for Liveness / Startup Probe Failures
        if any("liveness probe failed" in ev.lower() or "startup probe failed" in ev.lower() or "unhealthy" in ev.lower() for ev in snapshot.events) or \
           ("probe failed" in lower_text and primary_status.exit_code in [137, 143]):
            self._diagnose_probe_failure(snapshot, primary_status, result)
            return result

        # 3. Check for Missing Secret or ConfigMap (CreateContainerConfigError)
        if primary_status.state_reason in ["CreateContainerConfigError", "CreateContainerError"] or \
           any("secret" in ev.lower() and "not found" in ev.lower() for ev in snapshot.events) or \
           any("configmap" in ev.lower() and "not found" in ev.lower() for ev in snapshot.events):
            self._diagnose_missing_config(snapshot, primary_status, result)
            return result

        # 4. Check for Command Not Found (Exit Code 127)
        if primary_status.exit_code == 127 or "command not found" in lower_text or "exec format error" in lower_text:
            self._diagnose_command_not_found(snapshot, primary_status, result)
            return result

        # 5. Check for Permission Denied / Read-Only Filesystem (Exit Code 126)
        if primary_status.exit_code == 126 or "permission denied" in lower_text or "read-only file system" in lower_text:
            self._diagnose_permission_denied(snapshot, primary_status, result)
            return result

        # 6. Check for Native Segmentation Fault (Exit Code 139) or Windows Access Violation
        if primary_status.exit_code == 139 or "segmentation fault" in lower_text or "sigsegv" in lower_text:
            self._diagnose_segfault(snapshot, primary_status, result)
            return result
        elif primary_status.exit_code in [3221225477, 0xC0000005, -1073741819] or "0xc0000005" in lower_text:
            self._diagnose_windows_access_violation(snapshot, primary_status, result)
            return result

        # 7. Check for Application Abort / Assert Failure (Exit Code 134 = 128 + 6 SIGABRT)
        if primary_status.exit_code == 134 or "sigabrt" in lower_text or "assertion failed" in lower_text:
            self._diagnose_sigabrt(snapshot, primary_status, result)
            return result

        # 8. Check for Bus Error (Exit Code 138 = 128 + 10 SIGBUS)
        if primary_status.exit_code == 138 or "sigbus" in lower_text:
            self._diagnose_sigbus(snapshot, primary_status, result)
            return result

        # 9. Check for Broken Pipe (Exit Code 141 = 128 + 13 SIGPIPE)
        if primary_status.exit_code == 141 or "sigpipe" in lower_text or "broken pipe" in lower_text:
            self._diagnose_sigpipe(snapshot, primary_status, result)
            return result

        # 10. Check for User / System Interrupted (Exit Code 130 = 128 + 2 SIGINT)
        if primary_status.exit_code == 130 or "sigint" in lower_text:
            self._diagnose_sigint(snapshot, primary_status, result)
            return result

        # 11. Check for Node Eviction (DiskPressure / MemoryPressure)
        if snapshot.phase == "Failed" or "evicted" in lower_text or any("the node was low on resource" in ev.lower() for ev in snapshot.events):
            self._diagnose_node_eviction(snapshot, primary_status, result)
            return result

        # Default fallback: General Application Crash (Exit Code 1, 2, or unhandled)
        self._diagnose_generic_crash(snapshot, primary_status, result)
        return result

    def _diagnose_oomkilled(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "OOMKilled"
        result.confidence = "High"
        result.immediate_cause = f"Container '{cs.name}' terminated by Linux kernel cgroup OOM killer (Exit Code 137)."
        res = snapshot.resources.get(cs.name, ResourceConfig())

        mem_limit = res.memory_limit or "512Mi"
        result.root_cause = f"Container memory consumption exceeded the declared limit of {mem_limit}. " \
                            f"The Linux kernel cgroup memory controller invoked SIGKILL (signal 9) to prevent host exhaustion."

        result.evidence = [
            f"Exit Code: {cs.exit_code} (128 + 9 = SIGKILL)",
            f"Termination Reason: {cs.state_reason or 'OOMKilled'}",
            f"Declared Memory Limit: {mem_limit}",
            f"Pod QoS Class: {snapshot.qos_class}"
        ]

        result.timeline = [
            "Container process scheduled and began memory allocation.",
            f"Memory consumption crossed cgroup memory limit threshold ({mem_limit}).",
            "Kernel oom-killer selected container process and sent SIGKILL.",
            "Kubelet detected terminated container status and transitioned Pod to CrashLoopBackOff."
        ]

        # Generate YAML Patch
        new_limit = self._calculate_increased_memory(mem_limit)
        result.manifest_patch = f"""--- a/deployment.yaml
+++ b/deployment.yaml
@@ -18,4 +18,4 @@
           resources:
             limits:
-              memory: {mem_limit}
+              memory: {new_limit}
             requests:
-              memory: {res.memory_request or '256Mi'}
+              memory: {mem_limit}"""

        result.verification_commands = [
            f"kubectl top pod {snapshot.pod_name} -n {snapshot.namespace} --containers",
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace} | grep -E 'Limits|Requests|OOMKilled'",
            f"kubectl rollout status deployment/{self._derive_controller_name(snapshot.pod_name)} -n {snapshot.namespace}"
        ]

    def _diagnose_probe_failure(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "LivenessProbeTimeout"
        result.confidence = "High"
        result.immediate_cause = f"Container '{cs.name}' failed Kubernetes Liveness/Startup probe checks, prompting Kubelet to restart the container."

        probes = snapshot.probes.get(cs.name, {})
        liveness = probes.get("liveness", ProbeConfig())
        events_str = " ".join(snapshot.events)

        result.root_cause = f"Liveness probe targeting path '{liveness.path or '/healthz'}' timed out or returned HTTP failures. " \
                            f"The container took longer to become healthy than initialDelaySeconds ({liveness.initial_delay_seconds}s) " \
                            f"or exceeded failureThreshold ({liveness.failure_threshold} consecutive attempts)."

        result.evidence = [
            f"Exit Code: {cs.exit_code or 137} (Kubelet SIGTERM/SIGKILL termination)",
            f"Liveness Probe Configuration: delay={liveness.initial_delay_seconds}s, timeout={liveness.timeout_seconds}s, period={liveness.period_seconds}s, failures={liveness.failure_threshold}",
            f"Probe Failure Events: {self._extract_matching_event(snapshot.events, 'unhealthy') or 'Warning Unhealthy: Liveness probe failed'}"
        ]

        result.timeline = [
            "Container started and initiated internal application runtime.",
            f"Kubelet initiated probe polling after {liveness.initial_delay_seconds} seconds.",
            f"Probe attempts exceeded failure threshold ({liveness.failure_threshold}) due to startup latency or timeout.",
            "Kubelet sent SIGTERM, followed by SIGKILL, and scheduled container restart."
        ]

        # Generate YAML Patch to introduce startupProbe and adjust timeouts
        result.manifest_patch = f"""--- a/deployment.yaml
+++ b/deployment.yaml
@@ -22,6 +22,12 @@
+        startupProbe:
+          httpGet:
+            path: {liveness.path or '/healthz'}
+            port: {liveness.port or 8080}
+          failureThreshold: 30
+          periodSeconds: 10
         livenessProbe:
           httpGet:
             path: {liveness.path or '/healthz'}
             port: {liveness.port or 8080}
-          timeoutSeconds: {liveness.timeout_seconds}
+          timeoutSeconds: 3
-          initialDelaySeconds: {liveness.initial_delay_seconds}
+          initialDelaySeconds: 0"""

        result.verification_commands = [
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace} | grep -A 8 'Liveness:'",
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --tail=50",
            f"kubectl get events -n {snapshot.namespace} --field-selector involvedObject.name={snapshot.pod_name} --sort-by='.lastTimestamp'"
        ]

    def _diagnose_missing_config(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "MissingSecretOrConfigMap"
        result.confidence = "High"
        result.immediate_cause = f"Pod cannot start due to missing configuration dependency ({cs.state_reason or 'CreateContainerConfigError'})."

        missing_res = "database-secret"
        for ev in snapshot.events:
            m = re.search(r'(?:secret|configmap)\s*["\']([^"\']+)["\']\s*not found', ev, re.IGNORECASE)
            if m:
                missing_res = m.group(1)
                break

        result.root_cause = f"Container '{cs.name}' declares an environment variable or volume mount referencing '{missing_res}', which does not exist in namespace '{snapshot.namespace}'."
        # Built in two steps rather than as a nested f-string with escaped quotes.
        # That construct only parses on Python 3.12+ (PEP 701); on 3.9-3.11 it is a
        # hard SyntaxError, so this module would not import at all for most users
        # despite the documented 3.9+ support.
        _fallback_msg = 'secret "%s" not found' % missing_res
        _event_msg = self._extract_matching_event(snapshot.events, "not found") or _fallback_msg
        result.evidence = [
            f"Container State: {cs.state_reason or 'CreateContainerConfigError'}",
            f"Event Message: {_event_msg}",
        ]

        result.timeline = [
            "Kubelet scheduled pod and attempted container creation.",
            f"Kubelet queried namespace '{snapshot.namespace}' for referenced object '{missing_res}'.",
            "API server returned 404 Not Found.",
            "Container startup halted with CreateContainerConfigError."
        ]

        result.manifest_patch = f"""--- a/deployment.yaml
+++ b/deployment.yaml
@@ -15,4 +15,5 @@
               valueFrom:
                 secretKeyRef:
                   name: {missing_res}
                   key: password
+                  optional: true"""

        result.verification_commands = [
            f"kubectl get secrets,configmaps -n {snapshot.namespace}",
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace} | grep -E 'Error|Warning'",
            f"kubectl get events -n {snapshot.namespace} --field-selector involvedObject.name={snapshot.pod_name}"
        ]

    def _diagnose_command_not_found(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "CommandNotFound"
        result.confidence = "High"
        result.immediate_cause = f"Container entrypoint execution failed with Exit Code 127 (Command Not Found)."
        result.root_cause = "The executable binary or shell specified in command/args is missing from container image $PATH, or dynamically linked libraries (glibc/musl) are incompatible."

        result.evidence = [
            "Exit Code: 127",
            "Linux Error: 127 (Command Not Found / Exec format error)"
        ]

        result.timeline = [
            "Container filesystem mounted by container runtime.",
            "Runtime invoked execve() for configured entrypoint.",
            "Linux kernel returned ENOENT (No such file or directory).",
            "Container exited immediately with status code 127."
        ]

        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -10,3 +10,3 @@
-        command: ["/bin/sh", "-c", "start-service.sh"]
+        command: ["/bin/sh", "-c", "./start-service.sh"]"""

        result.verification_commands = [
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace} | grep -A 4 'Command:'",
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous"
        ]

    def _diagnose_permission_denied(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "PermissionDenied"
        result.confidence = "High"
        result.immediate_cause = f"Container process failed with Exit Code 126 or was blocked by filesystem security restrictions."
        result.root_cause = "The entrypoint script lacks execute permissions, container user lacks permissions to bind ports < 1024, or process attempted write operations to read-only rootfs."

        result.evidence = [
            f"Exit Code: {cs.exit_code or 126}",
            "Linux Error: 126 (Permission Denied / Container Cannot Run)"
        ]

        result.timeline = [
            "Container runtime created namespaces and applied securityContext.",
            "Process attempted restricted operation or non-executable binary call.",
            "Kernel rejected call with EACCES / EPERM.",
            "Container exited with code 126."
        ]

        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -12,4 +12,8 @@
         volumeMounts:
+        - name: tmp-dir
+          mountPath: /tmp
+      volumes:
+      - name: tmp-dir
+        emptyDir: {}"""

        result.verification_commands = [
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace} | grep -A 6 'Security Context:'",
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous"
        ]

    def _diagnose_segfault(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "Segfault"
        result.confidence = "High"
        result.immediate_cause = f"Container '{cs.name}' terminated abruptly due to memory access violation / SIGSEGV (Exit Code 139)."
        result.root_cause = "Process attempted to read or write to an unmapped virtual memory address. Common in native C/Go extensions, corrupt shared objects, or incompatible CPU architecture."

        result.evidence = [
            "Exit Code: 139 (128 + 11 = SIGSEGV)",
            "Linux Signal: SIGSEGV (Segmentation Violation)"
        ]

        result.timeline = [
            "Process executed native CPU instructions.",
            "Illegal memory pointer dereference or stack overflow occurred.",
            "Linux kernel delivered SIGSEGV and generated core dump event.",
            "Kubelet registered abnormal termination code 139."
        ]

        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -8,3 +8,3 @@
-        image: app:v2.1.0-native
+        image: app:v2.0.9-stable"""

        result.verification_commands = [
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous | grep -iE 'fault|dump|sigsegv'",
            f"kubectl describe node {snapshot.node_name} | grep -E 'Architecture|OS'"
        ]

    def _diagnose_node_eviction(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "NodeEviction"
        result.confidence = "High"
        result.immediate_cause = f"Pod evicted by Kubelet due to node-level resource starvation."
        result.root_cause = f"Node '{snapshot.node_name}' experienced DiskPressure or MemoryPressure exceeding eviction thresholds."

        result.evidence = [
            f"Pod Phase: {snapshot.phase}",
            f"Eviction Event: {self._extract_matching_event(snapshot.events, 'evicted') or 'The node was low on resource'}"
        ]

        result.timeline = [
            f"Node '{snapshot.node_name}' resource consumption crossed hard eviction threshold.",
            "Kubelet eviction manager selected pod based on QoS class priority.",
            "Pod received SIGTERM / SIGKILL and transitioned to Evicted state."
        ]

        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -16,4 +16,4 @@
           resources:
             requests:
-              memory: 128Mi
+              memory: 512Mi"""

        result.verification_commands = [
            f"kubectl describe node {snapshot.node_name} | grep -A 6 'Conditions:'",
            f"kubectl top node {snapshot.node_name}"
        ]

    def _diagnose_generic_crash(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "CrashLoopBackOff"
        result.confidence = "Medium"
        result.immediate_cause = f"Container '{cs.name}' exited with status code {cs.exit_code or 1} and is in CrashLoopBackOff."
        result.root_cause = "Application encountered an unhandled runtime exception or failed startup precondition."

        result.evidence = [
            f"Exit Code: {cs.exit_code or 1}",
            f"Restart Count: {cs.restart_count}",
            f"Last State: {cs.state_reason}"
        ]

        result.timeline = [
            "Container process initialized by Kubelet.",
            f"Process encountered fatal exception and terminated with exit code {cs.exit_code or 1}.",
            "Kubelet applied exponential backoff delay before restarting container."
        ]

        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -12,2 +12,4 @@
+        env:
+        - name: LOG_LEVEL
+          value: "DEBUG" """

        result.verification_commands = [
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous --tail=100",
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace}"
        ]

    def _diagnose_scheduling_failure(self, snapshot: PodSnapshot, result: RCAResult) -> None:
        result.category = "SchedulingFailure"
        result.confidence = "High"
        result.immediate_cause = "Pod cannot be scheduled onto any cluster node due to resource constraints or taints."
        sched_events = [ev for ev in snapshot.events if "failedscheduling" in ev.lower() or "insufficient" in ev.lower() or "node" in ev.lower()]
        event_msg = sched_events[0] if sched_events else "0/N nodes available: Insufficient memory or CPU"
        result.root_cause = f"The Kubernetes scheduler cannot place pod '{snapshot.pod_name}' on any cluster node. Observed: {event_msg}"
        result.evidence = [
            f"Pod Phase: {snapshot.phase}",
            f"Scheduler Event: {event_msg}"
        ]
        result.timeline = [
            "Pod submitted to API server.",
            "Scheduler evaluated cluster nodes against resource requests.",
            "All candidate nodes failed filter plugins (Insufficient cpu/memory or taints).",
            "Pod remained in Pending state."
        ]
        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -18,4 +18,4 @@
           resources:
             requests:
-              cpu: 4000m
+              cpu: 1000m
-              memory: 16Gi
+              memory: 4Gi"""
        result.verification_commands = [
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace} | grep -A 5 'Events:'",
            "kubectl get nodes -o wide",
            "kubectl top nodes"
        ]

    def _diagnose_windows_access_violation(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "Segfault"
        result.confidence = "High"
        result.immediate_cause = f"Windows container '{cs.name}' terminated with Access Violation 0xC0000005."
        result.root_cause = "Windows container process attempted an invalid memory access or unhandled C++ exception."
        result.evidence = [
            f"Exit Code: {cs.exit_code} (NTSTATUS 0xC0000005: STATUS_ACCESS_VIOLATION)",
            "Termination: Memory Access Violation"
        ]
        result.timeline = [
            "Container initialized on Windows node.",
            "Process executed native assembly instructions.",
            "Processor triggered memory access violation exception 0xC0000005.",
            "Process aborted abruptly."
        ]
        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -14,2 +14,2 @@
-        image: app-win:v1.2.0
+        image: app-win:v1.1.9-stable"""
        result.verification_commands = [
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous",
            f"kubectl describe node {snapshot.node_name} | grep -E 'OS|Kernel'"
        ]

    def _diagnose_sigabrt(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "ApplicationAbort"
        result.confidence = "High"
        result.immediate_cause = f"Container '{cs.name}' aborted execution via SIGABRT (Exit Code 134)."
        result.root_cause = "Process raised an assertion failure or called abort() in native runtime or JVM."
        result.evidence = [
            f"Exit Code: {cs.exit_code} (128 + 6 = SIGABRT)",
            "Signal: SIGABRT (Process Abort)"
        ]
        result.timeline = [
            "Process executed application runtime logic.",
            "Fatal assertion failed or abort() was explicitly invoked.",
            "Kernel terminated container with SIGABRT.",
            "Kubelet marked container as terminated with exit code 134."
        ]
        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -14,2 +14,2 @@
-        image: app:v2.0-canary
+        image: app:v1.9-stable"""
        result.verification_commands = [
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous | grep -iE 'assert|abort|fatal'",
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace}"
        ]

    def _diagnose_sigbus(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "BusError"
        result.confidence = "High"
        result.immediate_cause = f"Container '{cs.name}' terminated by SIGBUS memory alignment error (Exit Code 138)."
        result.root_cause = "Process attempted unaligned physical memory access or referenced an invalid mmap backing file."
        result.evidence = [
            f"Exit Code: {cs.exit_code} (128 + 10 = SIGBUS)",
            "Signal: SIGBUS (Bus Error / Unaligned Access)"
        ]
        result.timeline = [
            "Process executed memory operations.",
            "CPU raised unaligned memory access or invalid mmap fault.",
            "Kernel sent SIGBUS to process.",
            "Container terminated with exit code 138."
        ]
        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -14,2 +14,2 @@
-        image: app:v2.0-native
+        image: app:v1.9-stable"""
        result.verification_commands = [
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous | grep -iE 'bus error|sigbus'"
        ]

    def _diagnose_sigpipe(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "BrokenPipe"
        result.confidence = "High"
        result.immediate_cause = f"Container '{cs.name}' terminated by SIGPIPE write to closed pipe/socket (Exit Code 141)."
        result.root_cause = "Process attempted write to socket or pipe whose reading end was abruptly closed."
        result.evidence = [
            f"Exit Code: {cs.exit_code} (128 + 13 = SIGPIPE)",
            "Signal: SIGPIPE (Broken Pipe)"
        ]
        result.timeline = [
            "Process attempted network or pipe stream write.",
            "Remote endpoint closed socket without reading buffer.",
            "Kernel delivered default SIGPIPE signal terminating process.",
            "Kubelet marked container with exit code 141."
        ]
        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -14,2 +14,2 @@
-        image: app:v2.0
+        image: app:v2.0-resilient-socket"""
        result.verification_commands = [
            f"kubectl logs {snapshot.pod_name} -n {snapshot.namespace} -c {cs.name} --previous | grep -iE 'pipe|connection reset'"
        ]

    def _diagnose_sigint(self, snapshot: PodSnapshot, cs: ContainerStatus, result: RCAResult) -> None:
        result.category = "Interrupted"
        result.confidence = "High"
        result.immediate_cause = f"Container '{cs.name}' terminated by SIGINT / keyboard interrupt (Exit Code 130)."
        result.root_cause = "Process received SIGINT signal (128 + 2) indicating manual interruption."
        result.evidence = [
            f"Exit Code: {cs.exit_code} (128 + 2 = SIGINT)",
            "Signal: SIGINT (Interrupt)"
        ]
        result.timeline = [
            "Process executed normally.",
            "SIGINT delivered to process group.",
            "Process exited with code 130."
        ]
        result.manifest_patch = """--- a/deployment.yaml
+++ b/deployment.yaml
@@ -14,2 +14,2 @@
-        image: app:v2.0
+        image: app:v2.0-stable"""
        result.verification_commands = [
            f"kubectl describe pod {snapshot.pod_name} -n {snapshot.namespace}"
        ]

    def _calculate_increased_memory(self, mem_limit: str) -> str:
        if not mem_limit:
            return "1Gi"
        clean = mem_limit.strip()
        if clean.endswith("Ki"):
            val = int(clean[:-2])
            return f"{int(val * 1.5)}Ki"
        elif clean.endswith("k"):
            val = int(clean[:-1])
            return f"{int(val * 1.5)}k"
        elif clean.endswith("Mi"):
            val = int(clean[:-2])
            return f"{int(val * 1.5)}Mi"
        elif clean.endswith("M"):
            val = int(clean[:-1])
            return f"{int(val * 1.5)}M"
        elif clean.endswith("Gi"):
            val = float(clean[:-2])
            res = val * 1.5
            return f"{int(res)}Gi" if res.is_integer() else f"{res:.1f}Gi"
        elif clean.endswith("G"):
            val = float(clean[:-1])
            res = val * 1.5
            return f"{int(res)}G" if res.is_integer() else f"{res:.1f}G"
        elif clean.isdigit():
            val = int(clean)
            return str(int(val * 1.5))
        return "1Gi"

    def _derive_controller_name(self, pod_name: str) -> str:
        parts = pod_name.split("-")
        if not parts:
            return pod_name
        # StatefulSet ordinal suffix: <name>-<int> (e.g., db-cluster-0)
        if parts[-1].isdigit():
            return "-".join(parts[:-1])
        # Deployment replica set format: <name>-<replicaset_hash>-<pod_hash> (e.g. app-7d9c8b6f4-x9k2m)
        if len(parts) >= 3 and len(parts[-2]) >= 8 and len(parts[-1]) <= 6:
            return "-".join(parts[:-2])
        # DaemonSet format: <name>-<pod_hash> (e.g. fluentbit-daemon-x9k2m)
        if len(parts) >= 2 and len(parts[-1]) <= 6:
            return "-".join(parts[:-1])
        return pod_name

    def _extract_matching_event(self, events: List[str], keyword: str) -> Optional[str]:
        for ev in events:
            if keyword.lower() in ev.lower():
                return ev.strip()
        return None


# ----------------------------------------------------------------------
# Multi-Format Report Generator
# ----------------------------------------------------------------------

class RCAReportGenerator:
    """
    Renders diagnostic findings and manifest diffs into Markdown,
    clean unified diffs, structured JSON, or sanitized prompts.
    """

    def __init__(self, sanitizer: Optional[Sanitizer] = None) -> None:
        self.sanitizer = sanitizer or Sanitizer()

    def format_markdown(self, snapshot: PodSnapshot, rca: RCAResult, sanitize: bool = True) -> str:
        today = datetime.date.today().isoformat()
        pod_name = self.sanitizer.scrub(snapshot.pod_name) if sanitize else snapshot.pod_name
        namespace = self.sanitizer.scrub(snapshot.namespace) if sanitize else snapshot.namespace
        node_name = self.sanitizer.scrub(snapshot.node_name) if sanitize else snapshot.node_name
        imm_cause = self.sanitizer.scrub(rca.immediate_cause) if sanitize else rca.immediate_cause
        root_cause = self.sanitizer.scrub(rca.root_cause) if sanitize else rca.root_cause

        evidence_items = "\n".join(f"- {self.sanitizer.scrub(e) if sanitize else e}" for e in rca.evidence)
        timeline_items = "\n".join(f"{idx+1}. {self.sanitizer.scrub(t) if sanitize else t}" for idx, t in enumerate(rca.timeline))
        commands_items = "\n".join(f"- `{self.sanitizer.scrub(c) if sanitize else c}`" for c in rca.verification_commands)

        md = f"""# SRE Root Cause Analysis: Pod {pod_name}

## Executive Summary
- **Target Pod:** `{pod_name}`
- **Namespace:** `{namespace}`
- **Failure Classification:** `{rca.category}`
- **Diagnostic Confidence:** `{rca.confidence}`
- **Target Container:** `{rca.faulting_container}`
- **Report Generated:** `{today}`

---

## 1. Symptoms & Incident Observation
- **Immediate State:** {imm_cause}
- **Assigned Node:** `{node_name}`
- **Observed Exit Code:** `{rca.exit_code if rca.exit_code is not None else 'N/A'}`

### Corroborating Evidence
{evidence_items}

---

## 2. Root Cause Analysis
{root_cause}

### Diagnostic Timeline
{timeline_items}

---

## 3. Remediation Manifest Patch
Apply the following unified YAML diff to the workload controller manifest:

```diff
{rca.manifest_patch}
```

---

## 4. Verification & Validation Commands
Execute the following read-only commands to verify that the workload stabilizes following deployment:

{commands_items}

---

## 5. Architectural Recommendations
- Establish separate `startupProbe` definitions for workloads requiring cold-start caching or database migrations.
- Set container memory limits with at least 25% overhead above observed steady-state heap utilization.
- Implement QoS class guarantees for mission-critical microservices by setting equal CPU and memory requests and limits.
"""
        return md.strip()

    def format_json(self, snapshot: PodSnapshot, rca: RCAResult, sanitize: bool = True) -> str:
        data = {
            "incident_id": f"K8S-RCA-{hashlib.md5(snapshot.pod_name.encode('utf-8')).hexdigest()[:8].upper()}",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target": {
                "pod_name": self.sanitizer.scrub(snapshot.pod_name) if sanitize else snapshot.pod_name,
                "namespace": self.sanitizer.scrub(snapshot.namespace) if sanitize else snapshot.namespace,
                "node_name": self.sanitizer.scrub(snapshot.node_name) if sanitize else snapshot.node_name,
                "container": rca.faulting_container,
                "phase": snapshot.phase,
                "qos_class": snapshot.qos_class
            },
            "diagnosis": {
                "category": rca.category,
                "confidence": rca.confidence,
                "exit_code": rca.exit_code,
                "immediate_cause": self.sanitizer.scrub(rca.immediate_cause) if sanitize else rca.immediate_cause,
                "root_cause": self.sanitizer.scrub(rca.root_cause) if sanitize else rca.root_cause,
                "evidence": [self.sanitizer.scrub(e) if sanitize else e for e in rca.evidence],
                "timeline": [self.sanitizer.scrub(t) if sanitize else t for t in rca.timeline]
            },
            "remediation": {
                "manifest_patch": rca.manifest_patch,
                "verification_commands": [self.sanitizer.scrub(c) if sanitize else c for c in rca.verification_commands]
            }
        }
        return json.dumps(data, indent=2)

    def format_diff(self, rca: RCAResult) -> str:
        return rca.manifest_patch.strip()

    def format_prompt(self, snapshot: PodSnapshot, rca: RCAResult, sanitize: bool = True) -> str:
        raw_events = "\n".join(snapshot.events[:10])
        raw_logs = "\n".join(snapshot.previous_logs.get(rca.faulting_container, "").splitlines()[:50])
        if sanitize:
            raw_events = self.sanitizer.scrub(raw_events)
            raw_logs = self.sanitizer.scrub(raw_logs)

        prompt = f"""You are a Kubernetes Site Reliability Engineering specialist.
Analyze the following sanitized Kubernetes incident snapshot:

POD: {self.sanitizer.scrub(snapshot.pod_name) if sanitize else snapshot.pod_name}
NAMESPACE: {self.sanitizer.scrub(snapshot.namespace) if sanitize else snapshot.namespace}
FAILURE MODE: {rca.category} (Exit Code: {rca.exit_code})

EVENTS:
{raw_events or 'No warning events recorded.'}

PREVIOUS CONTAINER LOGS:
{raw_logs or 'No previous logs available.'}

DIAGNOSIS SUMMARY:
{self.sanitizer.scrub(rca.root_cause) if sanitize else rca.root_cause}

Verify the recommended manifest diff:
{rca.manifest_patch}
"""
        return prompt.strip()

    def format_html(self, snapshot: PodSnapshot, rca: RCAResult, sanitize: bool = True) -> str:
        import html
        pod_name = html.escape(self.sanitizer.scrub(snapshot.pod_name) if sanitize else snapshot.pod_name)
        namespace = html.escape(self.sanitizer.scrub(snapshot.namespace) if sanitize else snapshot.namespace)
        node_name = html.escape(self.sanitizer.scrub(snapshot.node_name) if sanitize else snapshot.node_name)
        category = html.escape(rca.category)
        confidence = html.escape(rca.confidence)
        container = html.escape(rca.faulting_container)
        exit_code = html.escape(str(rca.exit_code) if rca.exit_code is not None else "N/A")
        imm_cause = html.escape(self.sanitizer.scrub(rca.immediate_cause) if sanitize else rca.immediate_cause)
        root_cause = html.escape(self.sanitizer.scrub(rca.root_cause) if sanitize else rca.root_cause)
        diff_code = html.escape(rca.manifest_patch)

        evidence_html = "".join(f"<li>{html.escape(self.sanitizer.scrub(e) if sanitize else e)}</li>" for e in rca.evidence)
        timeline_html = "".join(f"<li>{html.escape(self.sanitizer.scrub(t) if sanitize else t)}</li>" for t in rca.timeline)
        commands_html = "".join(f"<li><code>{html.escape(self.sanitizer.scrub(c) if sanitize else c)}</code></li>" for c in rca.verification_commands)

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Kubernetes RCA Report: {pod_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
    .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 2rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
    h1 {{ color: #38bdf8; margin-top: 0; border-bottom: 2px solid #334155; padding-bottom: 0.75rem; font-size: 1.5rem; }}
    h2 {{ color: #94a3b8; font-size: 1.15rem; margin-top: 1.5rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: 600; font-size: 0.85rem; background: #dc2626; color: #fff; }}
    .badge-info {{ background: #0284c7; }}
    ul, ol {{ padding-left: 1.25rem; }}
    li {{ margin-bottom: 0.35rem; }}
    pre {{ background: #0b1120; border: 1px solid #334155; border-radius: 6px; padding: 1rem; overflow-x: auto; font-family: monospace; font-size: 0.9rem; color: #e2e8f0; }}
    code {{ background: #334155; padding: 0.15rem 0.35rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Kubernetes Root Cause Analysis: {pod_name}</h1>
    <p><strong>Namespace:</strong> {namespace} | <strong>Node:</strong> {node_name} | <strong>Container:</strong> {container}</p>
    <p><span class="badge">{category}</span> <span class="badge badge-info">Confidence: {confidence}</span> <span class="badge badge-info">Exit Code: {exit_code}</span></p>

    <h2>1. Symptoms & Incident Observation</h2>
    <p>{imm_cause}</p>
    <ul>{evidence_html}</ul>

    <h2>2. Root Cause Analysis</h2>
    <p>{root_cause}</p>
    <ol>{timeline_html}</ol>

    <h2>3. Declarative Remediation Diff</h2>
    <pre><code>{diff_code}</code></pre>

    <h2>4. Verification Runbook</h2>
    <ul>{commands_html}</ul>
  </div>
</body>
</html>"""
        return html_out.strip()

    def format_proof_of_work(self, snapshot: PodSnapshot, rca: RCAResult, sanitize: bool = True) -> str:
        pod_name = self.sanitizer.scrub(snapshot.pod_name) if sanitize else snapshot.pod_name
        namespace = self.sanitizer.scrub(snapshot.namespace) if sanitize else snapshot.namespace
        category = rca.category
        exit_code = str(rca.exit_code) if rca.exit_code is not None else "N/A"
        root_cause = self.sanitizer.scrub(rca.root_cause) if sanitize else rca.root_cause
        survival = f"{rca.survival_seconds:.1f}s" if rca.survival_seconds is not None else "N/A"

        commands_str = "\n".join(f"  - `{self.sanitizer.scrub(c) if sanitize else c}`" for c in rca.verification_commands)
        pow_md = f"""# SRE Portfolio Proof-of-Work: Kubernetes Incident RCA

> Sanitized technical case study for SRE and DevOps engineering portfolio documentation.

- **Incident Context:** Production Kubernetes workload `{pod_name}` in namespace `{namespace}` experienced recurring `{category}` restarts (Exit Code `{exit_code}`).
- **Telemetry Correlation:** Captured read-only pod state, container termination reasons, and namespace warning events. Calculated container survival duration ({survival}) and correlated Linux kernel signal math ({exit_code}) against probe timing and cgroup boundaries.
- **Root Cause Identified:** {root_cause}
- **Declarative Remediation:** Emitted unified YAML manifest diff adjusting container resource boundaries, configuring runtime heap ceilings, or decoupling initialization via dedicated startupProbe.
- **Verification Commands:**
{commands_str}
- **Measurable Impact:** Eliminated crashloop cascade, restored steady-state service availability, and prevented cluster node-level eviction pressure.
"""
        return pow_md.strip()


# ----------------------------------------------------------------------
# CLI Interface
# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kubernetes CrashLoopBackOff & OOMKilled RCA Engine (k8s-pod-rca)"
    )
    parser.add_argument(
        "-i", "--input",
        type=str,
        help="Path to file containing pod JSON, kubectl describe dump, or collector snapshot bundle"
    )
    parser.add_argument(
        "-f", "--format", "--output-format",
        dest="format",
        choices=["markdown", "json", "diff", "prompt", "html", "proof-of-work", "all"],
        default="markdown",
        help="Output report format (default: markdown)"
    )
    parser.add_argument(
        "--generate-proof-of-work",
        action="store_true",
        help="Generate a sanitized SRE portfolio proof-of-work case study"
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        default=True,
        help="Enable client-side PII sanitization (default: enabled)"
    )
    parser.add_argument(
        "--no-sanitize",
        dest="sanitize",
        action="store_false",
        help="Disable client-side PII sanitization"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file path (or directory when --format=all)"
    )
    return parser


def _main_impl() -> None:
    cli_parser = build_parser()
    args = cli_parser.parse_args()

    content = ""
    if args.input:
        in_path = Path(args.input)
        if not in_path.exists():
            print(f"Error: Input file '{args.input}' does not exist.", file=sys.stderr)
            sys.exit(1)
        content = in_path.read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    else:
        cli_parser.print_help()
        sys.exit(0)

    sanitizer = Sanitizer()
    parser = PodSnapshotParser(sanitizer=sanitizer)
    engine = K8sRCAEngine(sanitizer=sanitizer)
    generator = RCAReportGenerator(sanitizer=sanitizer)

    snapshot = parser.parse(content)
    rca = engine.analyze(snapshot)

    if args.generate_proof_of_work:
        args.format = "proof-of-work"

    if args.format == "all":
        out_dir = Path(args.output or "./k8s-rca-output")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "rca-report.md").write_text(generator.format_markdown(snapshot, rca, sanitize=args.sanitize), encoding="utf-8")
        (out_dir / "rca-data.json").write_text(generator.format_json(snapshot, rca, sanitize=args.sanitize), encoding="utf-8")
        (out_dir / "patch.diff").write_text(generator.format_diff(rca), encoding="utf-8")
        (out_dir / "llm-prompt.txt").write_text(generator.format_prompt(snapshot, rca, sanitize=args.sanitize), encoding="utf-8")
        (out_dir / "report.html").write_text(generator.format_html(snapshot, rca, sanitize=args.sanitize), encoding="utf-8")
        (out_dir / "proof-of-work.md").write_text(generator.format_proof_of_work(snapshot, rca, sanitize=args.sanitize), encoding="utf-8")
        print(f"Successfully exported all formats to: {out_dir}")
        return

    out_text = ""
    if args.format == "markdown":
        out_text = generator.format_markdown(snapshot, rca, sanitize=args.sanitize)
    elif args.format == "json":
        out_text = generator.format_json(snapshot, rca, sanitize=args.sanitize)
    elif args.format == "diff":
        out_text = generator.format_diff(rca)
    elif args.format == "prompt":
        out_text = generator.format_prompt(snapshot, rca, sanitize=args.sanitize)
    elif args.format == "html":
        out_text = generator.format_html(snapshot, rca, sanitize=args.sanitize)
    elif args.format == "proof-of-work":
        out_text = generator.format_proof_of_work(snapshot, rca, sanitize=args.sanitize)

    if args.output:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(out_text, encoding="utf-8")
        print(f"Successfully generated RCA report: {out_file}")
    else:
        print(out_text)
def main():
    """
    Hardened entry point.

    Diagnostic input arrives from operators and agents in every broken shape
    there is: an empty export, a directory, a truncated paste, a PDF renamed to
    .json, the wrong encoding. Each must produce one clear diagnostic line and a
    non-zero exit code. A Python traceback is the wrong failure mode here: it is
    unactionable for a technician, and for an agent it leaks absolute filesystem
    paths into a transcript while giving the model nothing it can act on.
    """
    try:
        return _main_impl() or 0
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.stderr.write("Error: interrupted.\n")
        return 1
    except IsADirectoryError:
        sys.stderr.write("Error: input path is a directory, not a file.\n")
        return 1
    except FileNotFoundError as exc:
        sys.stderr.write("Error: input file not found: %s\n" % exc)
        return 1
    except PermissionError as exc:
        sys.stderr.write("Error: permission denied reading input: %s\n" % exc)
        return 1
    except UnicodeError as exc:
        sys.stderr.write("Error: input encoding could not be decoded (%s).\n" % exc)
        return 1
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        sys.stderr.write("Error: input could not be parsed as valid telemetry "
                         "(%s: %s).\n" % (type(exc).__name__, exc))
        return 1
    except RecursionError:
        sys.stderr.write("Error: input is nested too deeply to parse safely.\n")
        return 1
    except MemoryError:
        sys.stderr.write("Error: input exhausted available memory; refusing to continue.\n")
        return 1
    except OSError as exc:
        sys.stderr.write("Error: could not read or write a file: %s\n" % exc)
        return 1
    except Exception as exc:
        sys.stderr.write("Error: unrecoverable problem processing this input "
                         "(%s: %s).\n" % (type(exc).__name__, exc))
        return 1

if __name__ == "__main__":
    sys.exit(main() or 0)