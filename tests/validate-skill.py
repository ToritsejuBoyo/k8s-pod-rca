#!/usr/bin/env python3
"""
Automated Validation Test Suite for k8s-pod-rca.

Tests 20 critical assertions across:
1. RCA Article Structure & Mandatory Headings
2. Deterministic Exit Code & Failure Classification
3. Client-Side PII Sanitization Guarantee (Zero Leaks)
4. Multi-Format Output Generation (Markdown, JSON, Unified Diff, LLM Prompt)
5. Zero-Emoji Compliance across code, fixtures, and templates (Rule 7)
"""

import json
import os
from pathlib import Path
import re
import sys
import unittest

# Setup import path for k8s_pod_rca module
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


class TestRCAStructureAndHeadings(unittest.TestCase):
    """Suite 1: Validates mandatory SRE RCA headings and content structure."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = PodSnapshotParser(sanitizer=self.sanitizer)
        self.engine = K8sRCAEngine(sanitizer=self.sanitizer)
        self.generator = RCAReportGenerator(sanitizer=self.sanitizer)

    def test_all_fixtures_generate_mandatory_headings(self) -> None:
        required_headings = [
            "# SRE Root Cause Analysis: Pod",
            "## Executive Summary",
            "## 1. Symptoms & Incident Observation",
            "### Corroborating Evidence",
            "## 2. Root Cause Analysis",
            "### Diagnostic Timeline",
            "## 3. Remediation Manifest Patch",
            "## 4. Verification & Validation Commands",
            "## 5. Architectural Recommendations"
        ]
        fixtures = list(FIXTURES_DIR.glob("fixture-*"))
        self.assertGreaterEqual(len(fixtures), 5, "Expected at least 5 synthetic fixtures")

        for fix in fixtures:
            content = fix.read_text(encoding="utf-8")
            snapshot = self.parser.parse(content)
            rca = self.engine.analyze(snapshot)
            md = self.generator.format_markdown(snapshot, rca)

            for heading in required_headings:
                self.assertIn(heading, md, f"Missing heading '{heading}' in {fix.name}")

    def test_unified_diff_is_present(self) -> None:
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        diff_out = self.generator.format_diff(rca)
        self.assertIn("--- a/deployment.yaml", diff_out)
        self.assertIn("+++ b/deployment.yaml", diff_out)
        self.assertIn("-              memory: 512Mi", diff_out)


class TestDeterministicFailureClassification(unittest.TestCase):
    """Suite 2: Validates exit code decoding and failure mode classification."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = PodSnapshotParser(sanitizer=self.sanitizer)
        self.engine = K8sRCAEngine(sanitizer=self.sanitizer)

    def test_oomkilled_cgroup_classification(self) -> None:
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "OOMKilled")
        self.assertEqual(rca.exit_code, 137)
        self.assertEqual(rca.confidence, "High")
        self.assertIn("cgroup", rca.root_cause.lower())

    def test_liveness_probe_timeout_classification(self) -> None:
        fix = FIXTURES_DIR / "fixture-liveness-probe-timeout.txt"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "LivenessProbeTimeout")
        self.assertEqual(rca.exit_code, 143)
        self.assertIn("liveness", rca.root_cause.lower())

    def test_missing_secret_classification(self) -> None:
        fix = FIXTURES_DIR / "fixture-configmap-missing-secret.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "MissingSecretOrConfigMap")
        self.assertIn("synthetic-db-credentials", rca.root_cause)

    def test_permission_denied_exit_126(self) -> None:
        fix = FIXTURES_DIR / "fixture-entrypoint-permission-denied.txt"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "PermissionDenied")
        self.assertEqual(rca.exit_code, 126)

    def test_segfault_native_crash_exit_139(self) -> None:
        fix = FIXTURES_DIR / "fixture-segfault-native-crash.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        self.assertEqual(rca.category, "Segfault")
        self.assertEqual(rca.exit_code, 139)


class TestPIISanitizationGuarantee(unittest.TestCase):
    """Suite 3: Verifies that sensitive cluster telemetry is completely masked."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()

    def test_masks_cluster_service_fqdn(self) -> None:
        raw = "Connecting to database.production.svc.cluster.local on port 5432"
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("production.svc.cluster.local", scrubbed)
        self.assertIn("service.namespace.svc.example.local", scrubbed)

    def test_masks_container_runtime_id(self) -> None:
        raw = "ContainerID: containerd://a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("a1b2c3d4e5f60718293a4b5c6d7e8f90", scrubbed)
        self.assertIn("containerd://[REDACTED_CONTAINER_ID]", scrubbed)

    def test_masks_bearer_jwt_tokens(self) -> None:
        jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50In0.ABCDEF1234567890"
        raw = f"Authorization: Bearer {jwt}"
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn(jwt, scrubbed)
        self.assertIn("[REDACTED_SECRET]", scrubbed)

    def test_masks_node_hostnames(self) -> None:
        raw = "Pod scheduled onto ip-10-0-4-12.ec2.internal"
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("ip-10-0-4-12", scrubbed)
        self.assertIn(".internal", scrubbed)

    def test_masks_ipv4_cluster_ips(self) -> None:
        raw = "Pod IP: 10.244.2.14, Host IP: 10.0.1.25"
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("10.244.2.14", scrubbed)
        self.assertNotIn("10.0.1.25", scrubbed)
        self.assertRegex(scrubbed, r"192\.0\.2\.\d+")


class TestMultiFormatOutputGeneration(unittest.TestCase):
    """Suite 4: Validates JSON schema, Markdown, and LLM prompt generation."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = PodSnapshotParser(sanitizer=self.sanitizer)
        self.engine = K8sRCAEngine(sanitizer=self.sanitizer)
        self.generator = RCAReportGenerator(sanitizer=self.sanitizer)

    def test_json_schema_validity(self) -> None:
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        json_str = self.generator.format_json(snapshot, rca)
        data = json.loads(json_str)

        self.assertIn("incident_id", data)
        self.assertIn("diagnosis", data)
        self.assertIn("remediation", data)
        self.assertEqual(data["diagnosis"]["category"], "OOMKilled")
        self.assertIsInstance(data["remediation"]["verification_commands"], list)

    def test_llm_prompt_structure(self) -> None:
        fix = FIXTURES_DIR / "fixture-liveness-probe-timeout.txt"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        rca = self.engine.analyze(snapshot)
        prompt = self.generator.format_prompt(snapshot, rca)
        self.assertIn("You are a Kubernetes Site Reliability Engineering specialist.", prompt)
        self.assertIn("FAILURE MODE: LivenessProbeTimeout", prompt)

    def test_empty_input_handling(self) -> None:
        snapshot = self.parser.parse("")
        self.assertEqual(snapshot.pod_name, "empty-input")
        rca = self.engine.analyze(snapshot)
        self.assertIsNotNone(rca)

    def test_whitespace_and_newlines_input(self) -> None:
        snapshot = self.parser.parse("   \n\n  \r\n  ")
        self.assertEqual(snapshot.pod_name, "empty-input")

    def test_cli_execution_and_file_export(self) -> None:
        import subprocess
        import tempfile
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                sys.executable,
                str(SCRIPTS_DIR / "k8s_pod_rca.py"),
                "-i", str(fix),
                "-f", "all",
                "-o", tmpdir
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertTrue((Path(tmpdir) / "rca-report.md").exists())
            self.assertTrue((Path(tmpdir) / "rca-data.json").exists())
            self.assertTrue((Path(tmpdir) / "patch.diff").exists())
            self.assertTrue((Path(tmpdir) / "llm-prompt.txt").exists())

    def test_init_container_crashloop_handling(self) -> None:
        init_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "synthetic-init-fail-pod", "namespace": "default"},
            "status": {
                "phase": "Pending",
                "initContainerStatuses": [
                    {
                        "name": "vault-init",
                        "ready": False,
                        "restartCount": 2,
                        "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                        "lastState": {"terminated": {"exitCode": 1, "reason": "Error"}}
                    }
                ],
                "containerStatuses": []
            }
        }
        snapshot = self.parser.parse(json.dumps(init_pod))
        self.assertEqual(len(snapshot.init_containers), 1)
        self.assertEqual(snapshot.init_containers[0].exit_code, 1)

    def test_runtime_qos_class_detection(self) -> None:
        fix = FIXTURES_DIR / "fixture-oomkilled-cgroup-limit.json"
        snapshot = self.parser.parse(fix.read_text(encoding="utf-8"))
        self.assertEqual(snapshot.qos_class, "Burstable")


class TestZeroEmojiCompliance(unittest.TestCase):
    """Suite 5: Strictly enforces Rule 7 (Zero-Emoji Policy across codebase)."""

    def test_code_and_docs_are_zero_emoji(self) -> None:
        emoji_pattern = re.compile(
            r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
        )
        files_to_check = [
            SCRIPTS_DIR / "k8s_pod_rca.py",
            REPO_ROOT / "SKILL.md",
            REPO_ROOT / "references" / "k8s-exit-codes-and-probes.md"
        ]
        fixtures = list(FIXTURES_DIR.glob("*"))
        files_to_check.extend(fixtures)

        for file_path in files_to_check:
            if not file_path.exists():
                continue
            text = file_path.read_text(encoding="utf-8")
            match = emoji_pattern.search(text)
            self.assertIsNone(
                match,
                f"Rule 7 Violation: Found emoji '{match.group(0) if match else ''}' in {file_path.name}"
            )


def suite() -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestRCAStructureAndHeadings))
    suite.addTests(loader.loadTestsFromTestCase(TestDeterministicFailureClassification))
    suite.addTests(loader.loadTestsFromTestCase(TestPIISanitizationGuarantee))
    suite.addTests(loader.loadTestsFromTestCase(TestMultiFormatOutputGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestZeroEmojiCompliance))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite())
    sys.exit(0 if result.wasSuccessful() else 1)
