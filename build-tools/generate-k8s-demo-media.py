#!/usr/bin/env python3
"""Generates HD demo.mp4 and animated demo.gif for k8s-pod-rca."""

import os
from pathlib import Path
import subprocess
from PIL import Image, ImageDraw, ImageFont

WIDTH = 1200
HEIGHT = 700
BG_COLOR = (15, 23, 42)  # Slate dark navy
HEADER_BG = (30, 41, 59)
TEXT_COLOR = (241, 245, 249)
MUTED_TEXT = (148, 163, 184)
PROMPT_COLOR = (56, 189, 248)  # Kubernetes Cyan / Blue
CMD_COLOR = (255, 255, 255)
GREEN_COLOR = (52, 211, 153)
YELLOW_COLOR = (251, 191, 36)
RED_COLOR = (248, 113, 113)
BLUE_COLOR = (96, 165, 250)
CYAN_COLOR = (56, 189, 248)


def create_base_canvas():
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Terminal top bar
    draw.rectangle([(0, 0), (WIDTH, 42)], fill=HEADER_BG)
    # Window control circles
    draw.ellipse([(16, 14), (28, 26)], fill=(239, 68, 68))
    draw.ellipse([(36, 14), (48, 26)], fill=(245, 158, 11))
    draw.ellipse([(56, 14), (68, 26)], fill=(16, 185, 129))

    # Title
    try:
        font = ImageFont.truetype("arial.ttf", 14)
    except Exception:
        font = ImageFont.load_default()
    draw.text(
        (WIDTH // 2 - 210, 12),
        "terminal - k8s-pod-rca (Kubernetes CrashLoopBackOff & OOMKilled Diagnostic Engine)",
        font=font,
        fill=MUTED_TEXT,
    )

    return img, draw


def render_frames(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        font = ImageFont.truetype("consola.ttf", 15)
        bold_font = ImageFont.truetype("consolab.ttf", 15)
        title_font = ImageFont.truetype("consolab.ttf", 17)
    except Exception:
        font = ImageFont.load_default()
        bold_font = font
        title_font = font

    screens = [
        # Frame 1: Empty prompt
        [
            (30, 65, "sre@k8s-bastion:~$ ", PROMPT_COLOR, bold_font),
            (210, 65, "", CMD_COLOR, bold_font),
        ],
        # Frame 2: Command typed
        [
            (30, 65, "sre@k8s-bastion:~$ ", PROMPT_COLOR, bold_font),
            (210, 65, "python scripts/k8s_pod_rca.py -i tests/fixtures/fixture-oomkilled-cgroup-limit.json --sanitize", CMD_COLOR, bold_font),
        ],
        # Frame 3: Processing & Executive Summary
        [
            (30, 65, "sre@k8s-bastion:~$ ", PROMPT_COLOR, bold_font),
            (210, 65, "python scripts/k8s_pod_rca.py -i tests/fixtures/fixture-oomkilled-cgroup-limit.json --sanitize", CMD_COLOR, bold_font),
            (30, 105, "==========================================================================================", MUTED_TEXT, font),
            (30, 125, "  KUBERNETES CRASHLOOPBACKOFF & OOMKILLED ROOT CAUSE ANALYSIS", CYAN_COLOR, title_font),
            (30, 150, "==========================================================================================", MUTED_TEXT, font),
            (30, 175, "  Target Workload:   synthetic-checkout-api-7d9c8b-x2k4 (Namespace: synthetic-workloads)", TEXT_COLOR, font),
            (30, 195, "  Data Sanitization: ACTIVE (RFC 5737 IPs, Masked Node Names, Redacted Container IDs)", GREEN_COLOR, bold_font),
            (30, 215, "  Classification:    OOMKilled (Exit Code: 137 | Linux Signal: 9 SIGKILL)", RED_COLOR, bold_font),
            (30, 235, "  Container State:   CrashLoopBackOff (Restart Count: 5 | QoS Class: Burstable)", YELLOW_COLOR, font),
            (30, 265, "  ROOT CAUSE DIAGNOSIS:", CYAN_COLOR, bold_font),
            (30, 290, "  * Container memory consumption exceeded the declared limit of 512Mi.", TEXT_COLOR, font),
            (30, 310, "  * Linux cgroup memory controller invoked SIGKILL (signal 9) to prevent node exhaustion.", TEXT_COLOR, font),
            (30, 330, "  * Application shopping cart session cache grew to 511.8MB during traffic peak.", YELLOW_COLOR, font),
            (30, 360, "  CORROBORATING EVIDENCE:", BLUE_COLOR, bold_font),
            (30, 385, "  - Exit Code: 137 (128 + 9 = SIGKILL)", TEXT_COLOR, font),
            (30, 405, "  - Termination Reason: OOMKilled | Memory Limit: 512Mi | Node: node-01.internal", MUTED_TEXT, font),
            (30, 425, "  - Kubelet Warning: Task in /kubepods/burstable/checkout-api killed by oom-killer (score 950)", RED_COLOR, font),
        ],
        # Frame 4: Unified Manifest Patch
        [
            (30, 65, "sre@k8s-bastion:~$ ", PROMPT_COLOR, bold_font),
            (210, 65, "python scripts/k8s_pod_rca.py -i tests/fixtures/fixture-oomkilled-cgroup-limit.json --sanitize", CMD_COLOR, bold_font),
            (30, 105, "## REMEDIATION MANIFEST PATCH (Ready for kubectl apply)", GREEN_COLOR, title_font),
            (30, 135, "--- a/deployment.yaml", MUTED_TEXT, font),
            (30, 155, "+++ b/deployment.yaml", MUTED_TEXT, font),
            (30, 175, "@@ -18,4 +18,4 @@", CYAN_COLOR, font),
            (30, 195, "           resources:", TEXT_COLOR, font),
            (30, 215, "             limits:", TEXT_COLOR, font),
            (30, 235, "-              memory: 512Mi", RED_COLOR, bold_font),
            (30, 255, "+              memory: 768Mi", GREEN_COLOR, bold_font),
            (30, 275, "             requests:", TEXT_COLOR, font),
            (30, 295, "-              memory: 256Mi", RED_COLOR, bold_font),
            (30, 315, "+              memory: 512Mi", GREEN_COLOR, bold_font),
            (30, 350, "## VERIFICATION RUNBOOK:", BLUE_COLOR, bold_font),
            (30, 375, "- kubectl top pod synthetic-checkout-api-7d9c8b-x2k4 -n synthetic-workloads --containers", CYAN_COLOR, font),
            (30, 395, "- kubectl describe pod synthetic-checkout-api-7d9c8b-x2k4 | grep -E 'Limits|Requests|OOMKilled'", CYAN_COLOR, font),
            (30, 415, "- kubectl rollout status deployment/synthetic-checkout-api -n synthetic-workloads", CYAN_COLOR, font),
            (30, 445, "[OK] Remediation diff synthesized with +50% memory headroom guarantee.", GREEN_COLOR, bold_font),
        ],
        # Frame 5: Multi-Format SRE Export
        [
            (30, 65, "sre@k8s-bastion:~$ ", PROMPT_COLOR, bold_font),
            (210, 65, "python scripts/k8s_pod_rca.py -i tests/fixtures/fixture-liveness-probe-timeout.txt -f all -o k8s-output", CMD_COLOR, bold_font),
            (30, 105, "==========================================================================================", MUTED_TEXT, font),
            (30, 125, "  MULTI-FORMAT SRE INCIDENT PUBLISHING PIPELINE", CYAN_COLOR, title_font),
            (30, 150, "==========================================================================================", MUTED_TEXT, font),
            (30, 175, "  Source Input:      fixture-liveness-probe-timeout.txt (kubectl describe + previous logs)", TEXT_COLOR, font),
            (30, 195, "  Identified Cause:  Liveness probe timeout (1s) triggered during cold start Flyway migration", YELLOW_COLOR, bold_font),
            (30, 215, "  Telemetry Masked:  ServiceAccount JWTs, Cluster FQDNs, Node Hostnames [Zero PII Leakage]", GREEN_COLOR, bold_font),
            (30, 245, "  EXPORTED ARTIFACTS:", BLUE_COLOR, bold_font),
            (30, 270, "  [+] Markdown:      k8s-output/rca-report.md (Executive Root Cause Analysis Document)", TEXT_COLOR, font),
            (30, 295, "  [+] JSON Schema:   k8s-output/rca-data.json (Slack/PagerDuty/ServiceNow Integration)", TEXT_COLOR, font),
            (30, 320, "  [+] Unified Patch: k8s-output/patch.diff    (startupProbe introduction + timeoutSeconds: 3)", TEXT_COLOR, font),
            (30, 345, "  [+] LLM Prompt:    k8s-output/llm-prompt.txt (Sanitized context for second-opinion LLMs)", TEXT_COLOR, font),
            (30, 380, "  STATUS: ROOT CAUSE RESOLVED (Zero Cluster Footprint. Read-Only Telemetry.)", GREEN_COLOR, bold_font),
            (30, 410, "sre@k8s-bastion:~$ ", PROMPT_COLOR, bold_font),
            (210, 410, "# 100% Deterministic. Pure Python Standard Library. Zero Cluster Mutation.", MUTED_TEXT, bold_font),
        ]
    ]

    durations = [2, 3, 4, 4, 4]  # Seconds per screen
    frame_idx = 0

    for screen_idx, (elements, dur) in enumerate(zip(screens, durations)):
        base_img, draw = create_base_canvas()
        for x, y, text, color, fnt in elements:
            draw.text((x, y), text, font=fnt, fill=color)

        fps = 4
        total_screen_frames = dur * fps
        for _ in range(total_screen_frames):
            frame_path = output_dir / f"frame_{frame_idx:04d}.png"
            base_img.save(frame_path)
            frame_idx += 1

    return frame_idx


def generate_mp4(frames_dir: Path, output_mp4: Path):
    cmd = [
        "ffmpeg", "-y",
        "-framerate", "4",
        "-i", str(frames_dir / "frame_%04d.png"),
        "-c:v", "libx264",
        "-profile:v", "high",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        str(output_mp4)
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def generate_gif(frames_dir: Path, output_gif: Path):
    palette_path = frames_dir / "palette.png"
    cmd_palette = [
        "ffmpeg", "-y",
        "-framerate", "4",
        "-i", str(frames_dir / "frame_%04d.png"),
        "-vf", "fps=4,scale=1200:-1:flags=lanczos,palettegen=stats_mode=diff",
        str(palette_path)
    ]
    subprocess.run(cmd_palette, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    cmd_gif = [
        "ffmpeg", "-y",
        "-framerate", "4",
        "-i", str(frames_dir / "frame_%04d.png"),
        "-i", str(palette_path),
        "-lavfi", "fps=4,scale=1200:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=3",
        str(output_gif)
    ]
    subprocess.run(cmd_gif, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    repo_root = Path(__file__).resolve().parent.parent
    assets_dir = repo_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    frames_dir = assets_dir / "frames"

    print("[*] Rendering terminal demo animation frames...")
    total_frames = render_frames(frames_dir)
    print(f"[+] Rendered {total_frames} frames.")

    mp4_path = assets_dir / "demo.mp4"
    gif_path = assets_dir / "demo.gif"

    print("[*] Compiling HD video (assets/demo.mp4)...")
    generate_mp4(frames_dir, mp4_path)
    print(f"[+] Generated: {mp4_path} ({mp4_path.stat().st_size / 1024:.1f} KB)")

    print("[*] Compiling animated GIF (assets/demo.gif)...")
    generate_gif(frames_dir, gif_path)
    print(f"[+] Generated: {gif_path} ({gif_path.stat().st_size / 1024:.1f} KB)")

    # Clean up intermediate frames
    for f in frames_dir.glob("*.png"):
        f.unlink()
    frames_dir.rmdir()
    print("[+] Cleaned up temporary rendering frames.")


if __name__ == "__main__":
    main()

