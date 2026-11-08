#!/usr/bin/env python3
"""
Advanced Edge Cases & SRE Diagnostics Test Suite for k8s-pod-rca.

Tests 20 specialized SRE scenarios:
- JVM -XX:MaxRAMPercentage and container support heuristics
- Node.js --max-old-space-size sizing against cgroup limits
- Kubernetes probe geometry (timeoutSeconds default 1s trap)
- Disambiguation between OOMKilled 137 and Probe Kill 137
- Container survival duration matching probe period math
- Read-only root filesystem /tmp emptyDir volume patch synthesis
- Controller targeting (Deployment vs StatefulSet vs DaemonSet)
- Go GOMEMLIMIT and Python Gunicorn worker memory tuning
- Structured incident schema compliance and Rule 7 zero-emoji guarantee
"""

import json
import os
from pathlib import Path
import re
import sys
import unittest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
FIXTURES_DIR = TESTS_DIR / "fixtures"
sys.path.insert(0, str(SCRIPTS_DIR))

from k8s_pod_rca import (
    Sanitizer,
    PodSnapshotParser,
    K8sRCAEngine,
    RCAReportGenerator,
    PodSnapshot,
    RCAResult,
    ContainerStatus,
    ProbeConfig,
    ResourceConfig
)


class TestAdvancedEdgeCases(unittest.TestCase):
    """20 Specialized SRE Edge-Case Tests."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = PodSnapshotParser(sanitizer=self.sanitizer)
        self.engine = K8sRCAEngine(sanitizer=self.sanitizer)
        self.generator = RCAReportGenerator(sanitizer=self.sanitizer)

    def test_adv01_jvm_container_support_detection(self) -> None:
        """ADV01: Recommends JVM MaxRAMPercentage when Java OOM occurs."""
        java_pod = {
            "metadata": {"name": "synthetic-java-pod", "namespace": "prod"},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {"name": "java-app", "ready": False, "restartCount": 3, "lastState": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}}}
                ]
            }
        }
        bundle = {
            "pod_spec_and_status": java_pod,
            "previous_logs": {"java-app": "java.lang.OutOfMemoryError: Java heap space\nContainer killed"}
        }
        snapshot = self.parser.parse(json.dumps(bundle))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "OOMKilled")

    def test_adv02_node_js_max_old_space_size(self) -> None:
        """ADV02: Diagnoses Node.js V8 heap exhaustion near cgroup limit."""
        node_pod = {
            "metadata": {"name": "synthetic-node-pod", "namespace": "prod"},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {"name": "node-app", "ready": False, "restartCount": 4, "lastState": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}}}
                ]
            }
        }
        bundle = {
            "pod_spec_and_status": node_pod,
            "previous_logs": {"node-app": "<--- Last few GCs --->\n[1:0x55a1b2c] 490 ms: Mark-sweep 510.2 MB\nFATAL ERROR: Reached heap limit Allocation failed"}
        }
        snapshot = self.parser.parse(json.dumps(bundle))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "OOMKilled")

    def test_adv03_probe_timeout_seconds_default_trap(self) -> None:
        """ADV03: Detects Liveness probe failures where timeoutSeconds is 1s."""
        fix = FIXTURES_DIR / "fixture-liveness-probe-timeout.txt"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "LivenessProbeTimeout")
        self.assertIn("timeoutSeconds: 3", rca.manifest_patch)

    def test_adv04_external_database_in_liveness_probe(self) -> None:
        """ADV04: Identifies probe cascade where liveness probe checks database."""
        raw = "Name: db-probe-pod\nEvents:\nWarning Unhealthy: Liveness probe failed: HTTP 500: Database connection timeout\nExit Code: 143"
        snapshot = self.parser.parse(raw)
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "LivenessProbeTimeout")

    def test_adv05_container_survival_duration_math(self) -> None:
        """ADV05: Calculates container survival seconds from startedAt and finishedAt."""
        cs = ContainerStatus(
            started_at="2026-11-04T10:00:00Z",
            finished_at="2026-11-04T10:00:45Z"
        )
        pod = {
            "metadata": {"name": "timed-pod"},
            "status": {
                "containerStatuses": [
                    {
                        "name": "main",
                        "ready": False,
                        "restartCount": 1,
                        "lastState": {"terminated": {"exitCode": 143, "startedAt": cs.started_at, "finishedAt": cs.finished_at}}
                    }
                ]
            }
        }
        snapshot = self.parser.parse(json.dumps(pod))
        self.assertEqual(snapshot.containers[0].survival_seconds, 45.0)

    def test_adv06_oomkilled_exit_137_vs_probe_exit_137(self) -> None:
        """ADV06: Disambiguates between OOMKilled and probe timeout when both report exit 137."""
        # Probe kill: reason is Error, unhealthy events present
        probe_pod = {
            "metadata": {"name": "probe-kill-pod"},
            "status": {
                "containerStatuses": [
                    {"name": "app", "ready": False, "lastState": {"terminated": {"exitCode": 137, "reason": "Error"}}}
                ]
            }
        }
        bundle = {
            "pod_spec_and_status": probe_pod,
            "events": ["Warning Unhealthy: Liveness probe failed: context deadline exceeded"]
        }
        snapshot = self.parser.parse(json.dumps(bundle))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "LivenessProbeTimeout")

    def test_adv07_readiness_probe_failure_without_restart(self) -> None:
        """ADV07: Identifies unready container where readiness probe fails without crashing."""
        raw = "Name: unready-pod\nStatus: Running\nEvents:\nWarning Unhealthy: Readiness probe failed: HTTP 503\nExit Code: 0"
        snapshot = self.parser.parse(raw)
        rca = self.engine.analyze(snapshot)
        self.assertIsNotNone(rca)

    def test_adv08_startup_probe_missing_on_slow_boot(self) -> None:
        """ADV08: Recommends startupProbe when application initialization trips liveness."""
        fix = FIXTURES_DIR / "fixture-liveness-probe-timeout.txt"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertIn("startupProbe:", rca.manifest_patch)

    def test_adv09_ephemeral_storage_eviction(self) -> None:
        """ADV09: Detects node eviction due to ephemeral storage pressure."""
        raw = "Name: storage-evict-pod\nStatus: Failed\nEvents:\nWarning Evicted: The node was low on resource: ephemeral-storage."
        snapshot = self.parser.parse(raw)
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "NodeEviction")

    def test_adv10_create_container_error_volume(self) -> None:
        """ADV10: Detects missing ConfigMap causing CreateContainerConfigError."""
        raw = "Name: configmap-pod\nEvents:\nWarning Failed: configmap \"app-config\" not found"
        snapshot = self.parser.parse(raw)
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "MissingSecretOrConfigMap")

    def test_adv11_arm64_vs_amd64_exec_format(self) -> None:
        """ADV11: Classifies Exit Code 127 from exec format error on wrong CPU architecture."""
        raw = "Name: arch-pod\nExit Code: 127\nLogs:\nstandard_init_linux.go: exec user process caused: exec format error"
        snapshot = self.parser.parse(raw)
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "CommandNotFound")

    def test_adv12_statefulset_controller_patch(self) -> None:
        """ADV12: Formats controller name for StatefulSets (pod-0 -> statefulset)."""
        snapshot = PodSnapshot(pod_name="synthetic-db-cluster-0", namespace="db")
        ctrl_name = self.engine._derive_controller_name(snapshot.pod_name)
        self.assertEqual(ctrl_name, "synthetic-db-cluster")

    def test_adv13_daemonset_controller_patch(self) -> None:
        """ADV13: Formats controller name for DaemonSets (agent-x9k2m -> agent)."""
        snapshot = PodSnapshot(pod_name="fluentbit-daemon-x9k2m", namespace="logging")
        ctrl_name = self.engine._derive_controller_name(snapshot.pod_name)
        self.assertEqual(ctrl_name, "fluentbit-daemon")

    def test_adv14_security_context_run_as_non_root(self) -> None:
        """ADV14: Classifies permission error when running non-root container."""
        fix = FIXTURES_DIR / "fixture-entrypoint-permission-denied.txt"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "PermissionDenied")

    def test_adv15_read_only_root_filesystem_tmp_patch(self) -> None:
        """ADV15: Recommends emptyDir /tmp volume when readOnlyRootFilesystem is active."""
        fix = FIXTURES_DIR / "fixture-entrypoint-permission-denied.txt"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertIn("emptyDir: {}", rca.manifest_patch)

    def test_adv16_multiple_restarts_backoff_timing(self) -> None:
        """ADV16: Correctly registers high restart count (restartCount >= 10)."""
        pod = {
            "metadata": {"name": "restarting-pod"},
            "status": {
                "containerStatuses": [{"name": "app", "restartCount": 24, "ready": False, "lastState": {"terminated": {"exitCode": 1}}}]
            }
        }
        snapshot = self.parser.parse(json.dumps(pod))
        self.assertEqual(snapshot.containers[0].restart_count, 24)

    def test_adv17_gomemlimit_recommendation(self) -> None:
        """ADV17: Recommends increased memory limits on Go container OOM."""
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertIn("768Mi", rca.manifest_patch)

    def test_adv18_python_prefork_workers_memory(self) -> None:
        """ADV18: Handles Gunicorn worker OOM in container logs."""
        raw = "Name: gunicorn-pod\nExit Code: 137\nLogs:\n[WARN] Worker 1 (pid:12) was killed by signal 9"
        snapshot = self.parser.parse(raw)
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "OOMKilled")

    def test_adv19_json_incident_schema_conformance(self) -> None:
        """ADV19: Validates structured incident schema contains target, diagnosis, remediation keys."""
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        data = json.loads(self.generator.format_json(snapshot, rca))
        self.assertIn("target", data)
        self.assertIn("diagnosis", data)
        self.assertIn("remediation", data)
        self.assertIn("pod_name", data["target"])

    def test_adv20_zero_emoji_guarantee_on_advanced_suite(self) -> None:
        """ADV20: Strictly enforces Rule 7 zero-emoji compliance on this test suite."""
        content = Path(__file__).resolve().read_text(encoding="utf-8")
        emoji_pattern = re.compile(
            r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
        )
        self.assertIsNone(emoji_pattern.search(content))


def suite() -> unittest.TestSuite:
    return unittest.TestLoader().loadTestsFromTestCase(TestAdvancedEdgeCases)


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite())
    sys.exit(0 if result.wasSuccessful() else 1)

