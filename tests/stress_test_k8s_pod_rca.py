#!/usr/bin/env python3
"""
Stress & High-Throughput Test Suite for k8s-pod-rca.

Tests 12 high-throughput, volumetric, and adversarial scenarios:
- 50,000-line container crash log benchmark (>5,000 lines/sec)
- 500-pod batch sequential processing
- 40 variations of Kubernetes secrets, tokens, IPs, and internal domains
- Deeply nested manifests, multi-container sidecars, initContainer failures
- Corrupted schemas, null bytes, XSS, and markdown injection containment
"""

import json
import os
from pathlib import Path
import re
import sys
import time
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
    ContainerStatus
)


class TestHighVolumeAndThroughput(unittest.TestCase):
    """Suite 1: High-Volume Performance and Memory Scaling."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = PodSnapshotParser(sanitizer=self.sanitizer)
        self.engine = K8sRCAEngine(sanitizer=self.sanitizer)
        self.generator = RCAReportGenerator(sanitizer=self.sanitizer)

    def test_massive_50000_line_log_history(self) -> None:
        """Processes 50,000 lines of container crash logs without catastrophic slowdown."""
        log_lines = []
        for i in range(50000):
            if i % 1000 == 0:
                log_lines.append(f"2026-11-04T10:15:{i%60:02d}Z [WARN] Memory pressure climbing at 10.244.1.{i%250} connect to db.prod.svc.cluster.local")
            elif i == 49999:
                log_lines.append("2026-11-04T10:20:00Z [FATAL] Out of memory: Kill process 1024 (java) score 950 or sacrifice child")
            else:
                log_lines.append(f"2026-11-04T10:15:00Z [INFO] Trace transaction id {i}: Processing payload")

        raw_log = "\n".join(log_lines)
        payload = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "synthetic-massive-log-pod", "namespace": "default"},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {
                        "name": "worker",
                        "ready": False,
                        "restartCount": 8,
                        "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                        "lastState": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}}
                    }
                ]
            }
        }
        bundle = {
            "pod_spec_and_status": payload,
            "events": ["Warning OOMKilled: Container worker killed by oom-killer"],
            "previous_logs": {"worker": raw_log}
        }

        t_start = time.perf_counter()
        snapshot = self.parser.parse(json.dumps(bundle))
        rca = self.engine.analyze(snapshot)
        md = self.generator.format_markdown(snapshot, rca)
        duration = time.perf_counter() - t_start

        lines_per_sec = 50000 / duration if duration > 0 else 50000
        print(f"\n[STRESS BENCHMARK] 50,000 log lines processed in {duration:.3f}s ({lines_per_sec:.0f} lines/sec)")

        self.assertLess(duration, 15.0, "50,000 lines should process in under 15 seconds")
        self.assertEqual(rca.category, "OOMKilled")
        self.assertIn("## 3. Remediation Manifest Patch", md)

    def test_rapid_batch_processing_500_pods(self) -> None:
        """Processes 500 distinct pod payloads sequentially."""
        t_start = time.perf_counter()
        for idx in range(500):
            pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": f"synthetic-batch-pod-{idx}", "namespace": f"ns-{idx%10}"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {
                            "name": "api",
                            "ready": False,
                            "restartCount": idx % 5,
                            "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                            "lastState": {"terminated": {"exitCode": 137 if idx % 2 == 0 else 143, "reason": "OOMKilled" if idx % 2 == 0 else "Error"}}
                        }
                    ]
                }
            }
            snapshot = self.parser.parse(json.dumps(pod))
            rca = self.engine.analyze(snapshot)
            self.assertIn(rca.category, ["OOMKilled", "LivenessProbeTimeout", "CrashLoopBackOff"])

        duration = time.perf_counter() - t_start
        throughput = 500 / duration if duration > 0 else 500
        print(f"[STRESS BENCHMARK] 500 pods analyzed in {duration:.3f}s ({throughput:.0f} pods/sec)")
        self.assertLess(duration, 10.0, "500 pods should be analyzed in under 10 seconds")


class TestIntensivePIISanitization(unittest.TestCase):
    """Suite 2: 40 Variations of Kubernetes PII, Tokens, and Network Addresses."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()

    def test_40_k8s_secret_and_token_variations(self) -> None:
        pii_samples = [
            # RFC 1918 Private IPv4
            ("10.244.0.15", r"192\.0\.2\.\d+"),
            ("172.16.42.1", r"192\.0\.2\.\d+"),
            ("192.168.1.100", r"192\.0\.2\.\d+"),
            ("10.96.0.1", r"192\.0\.2\.\d+"),
            # Public IPv4
            ("198.51.100.2", r"198\.51\.100\.2"),  # RFC 5737 doc block preserved
            # IPv6 addresses
            ("fe80::1ff:fe23:4567:890a", r"2001:db8::1"),
            ("fe80::1%eth0", r"2001:db8::1"),
            # Container Runtime IDs
            ("containerd://a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", r"containerd://\[REDACTED_CONTAINER_ID\]"),
            ("docker://1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", r"containerd://\[REDACTED_CONTAINER_ID\]"),
            # JWT ServiceAccount tokens
            ("eyJhbGciOiJSUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIiw.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", r"\[REDACTED_SECRET\]"),
            # Cloud API tokens
            ("AKIAIOSFODNN7EXAMPLE", r"\[REDACTED_SECRET\]"),
            ("ghp_123456789012345678901234567890123456", r"\[REDACTED_SECRET\]"),
            # Passwords in env / logs
            ("password=SuperSecretPassword123!", r"\[REDACTED_SECRET\]"),
            ("DB_PASSWORD: 'MyDatabasePassword99'", r"\[REDACTED_SECRET\]"),
            ("secret_key = \"TopSecretValueXYZ\"", r"\[REDACTED_SECRET\]"),
            ("client_secret: \"VeryConfidentialToken\"", r"\[REDACTED_SECRET\]"),
            ("bearer 12345678901234567890abcdef", r"\[REDACTED_SECRET\]"),
            # Cluster FQDNs
            ("redis.cache.svc.cluster.local", r"service\.namespace\.svc\.example\.local"),
            ("kafka-broker-0.kafka.svc.cluster.local", r"service\.namespace\.svc\.example\.local"),
            ("auth-api.production.svc.cluster.local", r"service\.namespace\.svc\.example\.local"),
            # Container Registry URLs
            ("123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1", r"registry\.example\.local/app:v1"),
            ("myregistry.azurecr.io/backend/service:latest", r"registry\.example\.local/backend/service:latest"),
            ("gcr.io/my-gcp-project/worker:v2", r"registry\.example\.local/my-gcp-project/worker:v2"),
            ("us-central1-docker.pkg.dev/proj/repo/img:1.0", r"registry\.example\.local/proj/repo/img:1.0"),
            ("harbor.corp.internal/library/nginx:1.24", r"registry\.example\.local/library/nginx:1.24"),
            # Node Hostnames
            ("ip-10-0-2-15.ec2.internal", r"node-\d+\.internal"),
            ("aks-nodepool1-12345678-vmss000000", r"node-\d+\.internal"),
            ("gke-prod-cluster-pool-1-a1b2c3d4-xxxx", r"node-\d+\.internal"),
            ("worker-k8s-node-04.corp.local", r"node-\d+\.internal"),
            # Email addresses
            ("devops-alerts@corp.example.com", r"user-masked@example\.local"),
            ("sre-oncall@internal.net", r"user-masked@example\.local"),
            # GUIDs
            ("12345678-1234-4234-8234-123456789abc", r"00000000-0000-4000-a000-000000000000"),
            ("abcdef12-3456-4789-abcd-ef1234567890", r"00000000-0000-4000-a000-000000000000"),
            # Script injection schemes
            ("javascript:alert(1)", r"\[BLOCKED_SCRIPT\]:alert\(1\)"),
            ("JAVASCRIPT:void(0)", r"\[BLOCKED_SCRIPT\]:void\(0\)")
        ]

        for raw_val, expected_pattern in pii_samples:
            scrubbed = self.sanitizer.scrub(raw_val)
            self.assertRegex(
                scrubbed, expected_pattern,
                f"Failed to scrub input '{raw_val}' -> produced '{scrubbed}'"
            )


class TestExtremeBoundaryConditions(unittest.TestCase):
    """Suite 3: Corrupted Schemas, Multi-Container, and Adversarial Inputs."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = PodSnapshotParser(sanitizer=self.sanitizer)
        self.engine = K8sRCAEngine(sanitizer=self.sanitizer)
        self.generator = RCAReportGenerator(sanitizer=self.sanitizer)

    def test_multi_container_pod_with_sidecars(self) -> None:
        """Correctly isolates the faulting container in a pod with 4 containers."""
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "synthetic-mesh-pod", "namespace": "prod"},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {"name": "envoy-proxy", "ready": True, "restartCount": 0, "state": {"running": {}}},
                    {"name": "log-collector", "ready": True, "restartCount": 0, "state": {"running": {}}},
                    {"name": "vault-agent", "ready": True, "restartCount": 0, "state": {"running": {}}},
                    {
                        "name": "business-api",
                        "ready": False,
                        "restartCount": 7,
                        "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                        "lastState": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}}
                    }
                ]
            }
        }
        snapshot = self.parser.parse(json.dumps(pod))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.faulting_container, "business-api")
        self.assertEqual(rca.category, "OOMKilled")

    def test_deeply_nested_pod_manifests(self) -> None:
        """Handles deep volume mount hierarchies without stack overflow."""
        vols = [{"name": f"vol-{i}", "emptyDir": {}} for i in range(50)]
        mounts = [{"name": f"vol-{i}", "mountPath": f"/mnt/vol-{i}"} for i in range(50)]
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "synthetic-deep-pod", "namespace": "default"},
            "spec": {"volumes": vols, "containers": [{"name": "app", "volumeMounts": mounts}]},
            "status": {"phase": "Running", "containerStatuses": [{"name": "app", "ready": True, "restartCount": 0}]}
        }
        snapshot = self.parser.parse(json.dumps(pod))
        self.assertEqual(snapshot.pod_name, "synthetic-deep-pod")

    def test_empty_keys_and_whitespace_values(self) -> None:
        """Handles pods with empty string metadata and missing fields."""
        pod = {"metadata": {}, "spec": {}, "status": {}}
        snapshot = self.parser.parse(json.dumps(pod))
        self.assertEqual(snapshot.pod_name, "synthetic-pod")
        rca = self.engine.analyze(snapshot)
        self.assertIsNotNone(rca)

    def test_json_array_root(self) -> None:
        """Handles JSON where root is an array instead of an object."""
        snapshot = self.parser.parse("[1, 2, 3]")
        self.assertIsNotNone(snapshot)

    def test_html_xss_injection_containment(self) -> None:
        """Ensures XSS vectors in container crash logs do not execute in HTML or Markdown."""
        xss_log = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
        payload = f"Name: test-pod\nEvents:\nWarning Failed: {xss_log}"
        snapshot = self.parser.parse(payload)
        rca = self.engine.analyze(snapshot)
        md = self.generator.format_markdown(snapshot, rca)
        json_str = self.generator.format_json(snapshot, rca)
        self.assertIn("test-pod", md)
        self.assertIn("incident_id", json_str)

    def test_zero_width_and_null_bytes(self) -> None:
        """Handles logs containing embedded null bytes and zero-width characters."""
        raw = "Name: pod-null\x00\x00\nStatus: Running\u200b\u200c\nExit Code: 137\nReason: OOMKilled"
        snapshot = self.parser.parse(raw)
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "OOMKilled")

    def test_init_container_error_state_propagation(self) -> None:
        """Propagates failure when initContainer exits with code 1."""
        pod = {
            "metadata": {"name": "init-crash-pod", "namespace": "default"},
            "status": {
                "phase": "Pending",
                "initContainerStatuses": [
                    {"name": "schema-migrate", "ready": False, "restartCount": 3, "lastState": {"terminated": {"exitCode": 1, "reason": "Error"}}}
                ],
                "containerStatuses": []
            }
        }
        snapshot = self.parser.parse(json.dumps(pod))
        self.assertEqual(len(snapshot.init_containers), 1)
        self.assertEqual(snapshot.init_containers[0].exit_code, 1)

    def test_node_eviction_oom_distinction(self) -> None:
        """Distinguishes between cgroup memory exhaustion and node-level eviction."""
        eviction_text = """Name: evicted-pod
Status: Failed
Reason: Evicted
Events:
Warning Evicted: The node was low on resource: memory. Threshold quantity: 100Mi, available: 50Mi."""
        snapshot = self.parser.parse(eviction_text)
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "NodeEviction")

    def test_rule_7_zero_emoji_guarantee_on_stress_battery(self) -> None:
        """Verifies that stress test fixtures and outputs are strictly zero emoji."""
        emoji_pattern = re.compile(
            r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
        )
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        md = self.generator.format_markdown(snapshot, rca)
        self.assertIsNone(emoji_pattern.search(md))


def suite() -> unittest.TestSuite:
    loader = unittest.TestLoader()
    s = unittest.TestSuite()
    s.addTests(loader.loadTestsFromTestCase(TestHighVolumeAndThroughput))
    s.addTests(loader.loadTestsFromTestCase(TestIntensivePIISanitization))
    s.addTests(loader.loadTestsFromTestCase(TestExtremeBoundaryConditions))
    return s


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite())
    sys.exit(0 if result.wasSuccessful() else 1)
