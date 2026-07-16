"""Render the README GIF from real EnvWitness command output."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
CAPSULE_DIRECTORY = ROOT / ".envwitness" / "demo-gif"
OUTPUT_PATH = ROOT / "assets" / "demo.gif"
WIDTH = 1200
HEIGHT = 680


def run_command(arguments: tuple[str, ...]) -> str:
    """Run one repository command and return normalized output."""
    environment = os.environ.copy()
    environment["COLUMNS"] = "100"
    completed_process = subprocess.run(  # noqa: S603
        arguments,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = completed_process.stdout.strip()
    if completed_process.returncode != 0:
        error_output = (completed_process.stdout + completed_process.stderr).strip()
        raise RuntimeError(
            f"Demo command failed with exit code {completed_process.returncode}: {error_output}"
        )
    return output.replace(str(ROOT), ".").replace("\\", "/")


def select_font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Load a readable cross-platform monospace font or Pillow's fallback."""
    candidates = (
        Path("C:/Windows/Fonts/CascadiaMono.ttf"),
        Path("C:/Windows/Fonts/consola.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
        Path("/System/Library/Fonts/Menlo.ttc"),
    )
    if bold:
        bold_candidates = (
            Path("C:/Windows/Fonts/CascadiaMono-Bold.ttf"),
            Path("C:/Windows/Fonts/consolab.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"),
        )
        candidates = bold_candidates + candidates
    for candidate in candidates:
        if candidate.is_file():
            return ImageFont.truetype(str(candidate), size=size)
    return ImageFont.load_default(size=size)


def wrap_terminal_lines(lines: list[tuple[str, str]], limit: int = 75) -> list[tuple[str, str]]:
    """Wrap terminal lines while preserving their semantic color role."""
    wrapped: list[tuple[str, str]] = []
    for value, role in lines:
        remaining = value
        while len(remaining) > limit:
            split_at = remaining.rfind(" ", 0, limit + 1)
            if split_at < 1:
                split_at = limit
            wrapped.append((remaining[:split_at], role))
            remaining = "  " + remaining[split_at:].lstrip()
        wrapped.append((remaining, role))
    return wrapped


def render_frame(lines: list[tuple[str, str]], caption: str) -> Image.Image:
    """Render one terminal frame with stable dimensions and accessible contrast."""
    image = Image.new("RGB", (WIDTH, HEIGHT), "#f3f5f4")
    drawing = ImageDraw.Draw(image)
    title_font = select_font(26, bold=True)
    body_font = select_font(23)
    caption_font = select_font(20, bold=True)

    drawing.rounded_rectangle((50, 42, 1150, 620), radius=8, fill="#111b1a")
    drawing.rectangle((50, 42, 1150, 98), fill="#20302e")
    drawing.ellipse((75, 61, 91, 77), fill="#d95d4f")
    drawing.ellipse((102, 61, 118, 77), fill="#e3aa3d")
    drawing.ellipse((129, 61, 145, 77), fill="#44a06f")
    drawing.text((175, 58), "EnvWitness / local terminal", font=title_font, fill="#edf5f2")
    drawing.text((58, 640), caption, font=caption_font, fill="#194f49")

    colors = {
        "command": "#65d6c2",
        "success": "#9ee493",
        "heading": "#f2c66d",
        "output": "#d8e2df",
        "muted": "#91a6a1",
    }
    y_position = 126
    for value, role in wrap_terminal_lines(lines):
        drawing.text((82, y_position), value, font=body_font, fill=colors[role])
        y_position += 34
        if y_position > 590:
            break
    return image


def build_frames() -> list[Image.Image]:
    """Execute the demo workflow and render progressive terminal states."""
    CAPSULE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    working_path = CAPSULE_DIRECTORY / "working.evw"
    failing_path = CAPSULE_DIRECTORY / "failing.evw"
    working_capture = run_command(
        (
            sys.executable,
            "-m",
            "envwitness",
            "capture",
            "--project-root",
            str(ROOT),
            "--output",
            str(working_path),
            "--",
            sys.executable,
            "-c",
            "print('checkout passed')",
        )
    )
    failing_capture = run_command(
        (
            sys.executable,
            "-m",
            "envwitness",
            "capture",
            "--project-root",
            str(ROOT),
            "--output",
            str(failing_path),
            "--",
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.stderr.write('Authorization: Bearer demo-token-value-1234567890\\n'); "
                "sys.exit(1)"
            ),
        )
    )
    verification = run_command((sys.executable, "-m", "envwitness", "verify", str(working_path)))
    comparison = run_command(
        (
            sys.executable,
            "-m",
            "envwitness",
            "compare",
            str(working_path),
            str(failing_path),
            "--format",
            "markdown",
        )
    )
    comparison_lines = [line for line in comparison.splitlines() if line.strip()]

    return [
        render_frame(
            [
                ("$ envwitness capture --output working.evw -- python -m pytest", "command"),
                *[(line, "success") for line in working_capture.splitlines()],
                ("", "output"),
                ("$ envwitness capture --output failing.evw -- python -m pytest", "command"),
                *[(line, "success") for line in failing_capture.splitlines()],
            ],
            "Capture only the evidence you can explain.",
        ),
        render_frame(
            [
                ("$ envwitness verify working.evw", "command"),
                (verification, "success"),
                ("", "output"),
                ("$ envwitness compare working.evw failing.evw", "command"),
                ("Comparing semantic fact keys...", "muted"),
            ],
            "Verify before opening or sharing a capsule.",
        ),
        render_frame(
            [
                ("$ envwitness compare working.evw failing.evw", "command"),
                *[
                    (
                        line,
                        "heading" if line.startswith(("#", "1.", "2.", "3.")) else "output",
                    )
                    for line in comparison_lines[:11]
                ],
            ],
            "Find the meaningful drift, not another wall of logs.",
        ),
    ]


def main() -> None:
    """Write an optimized looping GIF to the documented asset path."""
    frames = build_frames()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        OUTPUT_PATH,
        save_all=True,
        append_images=frames[1:],
        duration=(1600, 1400, 3400),
        disposal=2,
        loop=0,
        optimize=False,
    )
    print(f"Created {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
