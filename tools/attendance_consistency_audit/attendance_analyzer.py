#!/usr/bin/env python3
"""Attendance Consistency Analyzer.

Accepts manually recorded attendance counts and displayed dashboard percentages
(via JSON file or interactive prompt), evaluates candidate calculation and
rounding methods, checks overall aggregation consistency, and outputs a
structured comparison table / Markdown evidence report.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_EVEN, ROUND_HALF_UP, ROUND_UP
import json
from pathlib import Path
import sys
from typing import Any


ROUNDING_MODES: dict[str, str] = {
    "half_up": ROUND_HALF_UP,
    "half_even": ROUND_HALF_EVEN,
    "floor": ROUND_DOWN,
    "ceil": ROUND_UP,
}


@dataclass
class SubjectRecord:
    """Manually recorded counts and displayed percentage for a single subject."""

    name: str
    present: int
    total_held: int
    displayed_pct: float | None = None
    displayed_decimals: int = 2
    absent: int | None = None
    excused: int = 0
    late: int = 0
    cancelled: int = 0
    weight: float = 1.0
    notes: str = ""


@dataclass
class OverallRecord:
    """Manually recorded overall summary values shown on the dashboard."""

    displayed_pct: float | None = None
    displayed_decimals: int = 2
    displayed_present: int | None = None
    displayed_total: int | None = None
    notes: str = ""


@dataclass
class FormulaResult:
    """Result of evaluating one percentage formula and its rounding variants."""

    name: str
    numerator: Decimal
    denominator: Decimal
    exact_pct: Decimal | None
    rounded: dict[str, Decimal] = field(default_factory=dict)


def quantize_pct(value: Decimal, decimals: int, mode: str) -> Decimal:
    """Round a Decimal percentage using the specified Decimal rounding mode."""
    quantum = Decimal("1") if decimals == 0 else Decimal(f"1e-{decimals}")
    return value.quantize(quantum, rounding=ROUNDING_MODES[mode])


def compute_formula(
    name: str,
    numerator: Decimal,
    denominator: Decimal,
    decimals: int,
) -> FormulaResult:
    """Compute exact percentage and all rounding variants for a fraction."""
    if denominator <= 0:
        return FormulaResult(name=name, numerator=numerator, denominator=denominator, exact_pct=None)
    exact = (numerator / denominator) * Decimal("100")
    rounded = {
        mode_name: quantize_pct(exact, decimals, mode_name)
        for mode_name in ROUNDING_MODES
    }
    return FormulaResult(
        name=name,
        numerator=numerator,
        denominator=denominator,
        exact_pct=exact,
        rounded=rounded,
    )


def evaluate_subject(rec: SubjectRecord) -> list[FormulaResult]:
    """Evaluate candidate per-subject attendance formulas."""
    p = Decimal(rec.present)
    t = Decimal(rec.total_held)
    e = Decimal(rec.excused)
    l = Decimal(rec.late)
    c = Decimal(rec.cancelled)
    d = rec.displayed_decimals

    candidates: list[tuple[str, Decimal, Decimal]] = [
        ("present / total_held", p, t),
    ]
    if rec.excused > 0:
        candidates.append(("(present + excused) / total_held", p + e, t))
        candidates.append(("present / (total_held - excused)", p, t - e))
    if rec.late > 0:
        candidates.append(("(present + 0.5*late) / total_held", p + Decimal("0.5") * l, t))
        candidates.append(("(present + late) / total_held", p + l, t))
    if rec.cancelled > 0:
        candidates.append(("present / (total_held + cancelled)", p, t + c))

    return [compute_formula(name, num, den, d) for name, num, den in candidates]


def validate_subject_logic(rec: SubjectRecord) -> list[str]:
    """Check for internal count contradictions on a subject record."""
    anomalies: list[str] = []
    if rec.total_held < 0 or rec.present < 0 or rec.excused < 0 or rec.late < 0 or rec.cancelled < 0:
        anomalies.append("Negative count entered.")
    if rec.present > rec.total_held:
        anomalies.append(f"present ({rec.present}) > total_held ({rec.total_held}).")
    if rec.excused > rec.total_held:
        anomalies.append(f"excused ({rec.excused}) > total_held ({rec.total_held}).")
    if rec.absent is not None:
        accounted = rec.present + rec.absent + rec.excused + rec.late
        if accounted != rec.total_held:
            anomalies.append(
                f"present+absent+excused+late ({accounted}) != total_held ({rec.total_held})."
            )
    if rec.displayed_pct is not None and not (0.0 <= rec.displayed_pct <= 100.0):
        anomalies.append(f"displayed_pct ({rec.displayed_pct}%) outside [0, 100].")
    return anomalies


def find_matching_variants(
    displayed_pct: float | None,
    decimals: int,
    results: list[FormulaResult],
) -> tuple[list[str], tuple[str, str, Decimal] | None]:
    """Return exact rounded matches and the closest (formula, mode, signed_delta)."""
    if displayed_pct is None:
        return [], None

    disp = Decimal(str(displayed_pct))
    matches: list[str] = []
    closest: tuple[str, str, Decimal] | None = None

    for res in results:
        if res.exact_pct is None:
            continue
        for mode_name, rounded_val in res.rounded.items():
            delta = disp - rounded_val
            if rounded_val == quantize_pct(disp, decimals, "half_up"):
                matches.append(f"{res.name} [{mode_name}] -> {rounded_val}%")
            if closest is None or abs(delta) < abs(closest[2]):
                closest = (res.name, mode_name, delta)

    return matches, closest


def evaluate_overall(
    subjects: list[SubjectRecord],
    overall: OverallRecord,
) -> tuple[list[FormulaResult], list[str]]:
    """Evaluate candidate overall aggregation formulas across subjects."""
    anomalies: list[str] = []
    if not subjects:
        return [], anomalies

    d = overall.displayed_decimals
    sum_present = sum(s.present for s in subjects)
    sum_total = sum(s.total_held for s in subjects)
    sum_excused = sum(s.excused for s in subjects)
    sum_cancelled = sum(s.cancelled for s in subjects)

    if overall.displayed_present is not None and overall.displayed_present != sum_present:
        anomalies.append(
            f"Overall displayed_present ({overall.displayed_present}) != sum of subject present ({sum_present})."
        )
    if overall.displayed_total is not None and overall.displayed_total != sum_total:
        anomalies.append(
            f"Overall displayed_total ({overall.displayed_total}) != sum of subject total_held ({sum_total})."
        )

    results: list[FormulaResult] = [
        compute_formula("Pooled: sum(present) / sum(total_held)", Decimal(sum_present), Decimal(sum_total), d),
    ]
    if sum_excused > 0:
        results.append(
            compute_formula(
                "Pooled: sum(present + excused) / sum(total_held)",
                Decimal(sum_present + sum_excused),
                Decimal(sum_total),
                d,
            )
        )
        results.append(
            compute_formula(
                "Pooled: sum(present) / sum(total_held - excused)",
                Decimal(sum_present),
                Decimal(sum_total - sum_excused),
                d,
            )
        )
    if sum_cancelled > 0:
        results.append(
            compute_formula(
                "Pooled: sum(present) / sum(total_held + cancelled)",
                Decimal(sum_present),
                Decimal(sum_total + sum_cancelled),
                d,
            )
        )

    valid_subjects = [s for s in subjects if s.total_held > 0]
    if valid_subjects:
        exact_subj_pcts = [Decimal(s.present) / Decimal(s.total_held) for s in valid_subjects]
        n = Decimal(len(valid_subjects))
        results.append(
            compute_formula("Unweighted mean of subject exact ratios", sum(exact_subj_pcts), n, d)
        )

        # Mean of subject percentages rounded to subject display decimals
        for mode_name in ("half_up", "floor"):
            rounded_ratios = [
                quantize_pct((Decimal(s.present) / Decimal(s.total_held)) * Decimal("100"), s.displayed_decimals, mode_name)
                / Decimal("100")
                for s in valid_subjects
            ]
            results.append(
                compute_formula(f"Unweighted mean of [{mode_name}] rounded subject %", sum(rounded_ratios), n, d)
            )

        if any(s.weight != 1.0 for s in valid_subjects):
            weighted_num = sum(
                (Decimal(s.present) / Decimal(s.total_held)) * Decimal(str(s.weight))
                for s in valid_subjects
            )
            weighted_den = sum(Decimal(str(s.weight)) for s in valid_subjects)
            results.append(
                compute_formula("Weighted mean by subject weight/credits", weighted_num, weighted_den, d)
            )

    return results, anomalies


def load_from_json(path: Path) -> tuple[dict[str, Any], list[SubjectRecord], OverallRecord]:
    """Load attendance figures from a JSON file."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    meta = raw.get("metadata", {})
    subjects = [SubjectRecord(**item) for item in raw.get("subjects", [])]
    overall = OverallRecord(**raw.get("overall", {}))
    return meta, subjects, overall


def prompt_int(label: str, default: int | None = None, optional: bool = False) -> int | None:
    """Prompt for an integer on stdin."""
    suffix = f" [{default}]" if default is not None else (" [optional]" if optional else "")
    while True:
        val = input(f"{label}{suffix}: ").strip()
        if not val:
            if default is not None:
                return default
            if optional:
                return None
            print("Value required.")
            continue
        try:
            return int(val)
        except ValueError:
            print("Enter a valid integer.")


def prompt_float(label: str, optional: bool = True) -> float | None:
    """Prompt for a float on stdin."""
    suffix = " [optional]" if optional else ""
    while True:
        val = input(f"{label}{suffix}: ").strip()
        if not val:
            return None if optional else 0.0
        try:
            return float(val.rstrip("%"))
        except ValueError:
            print("Enter a valid number.")


def interactive_entry() -> tuple[dict[str, Any], list[SubjectRecord], OverallRecord]:
    """Interactively collect manually observed attendance records."""
    print("Interactive Attendance Entry (press Enter on blank subject name to finish)\n")
    subjects: list[SubjectRecord] = []
    while True:
        name = input("Subject name/code: ").strip()
        if not name:
            break
        present = prompt_int("  Present count")
        total_held = prompt_int("  Total classes held")
        absent = prompt_int("  Absent count", optional=True)
        excused = prompt_int("  Excused/OD/Medical count", default=0)
        late = prompt_int("  Late count", default=0)
        cancelled = prompt_int("  Cancelled count", default=0)
        displayed_pct = prompt_float("  Displayed % on dashboard")
        decimals = prompt_int("  Displayed decimal places", default=2)
        subjects.append(
            SubjectRecord(
                name=name,
                present=present or 0,
                total_held=total_held or 0,
                absent=absent,
                excused=excused or 0,
                late=late or 0,
                cancelled=cancelled or 0,
                displayed_pct=displayed_pct,
                displayed_decimals=decimals if decimals is not None else 2,
            )
        )
        print()

    print("Overall summary section:")
    overall_pct = prompt_float("  Displayed overall %")
    overall_decimals = prompt_int("  Overall decimal places", default=2)
    overall_present = prompt_int("  Displayed overall present count", optional=True)
    overall_total = prompt_int("  Displayed overall total count", optional=True)
    overall = OverallRecord(
        displayed_pct=overall_pct,
        displayed_decimals=overall_decimals if overall_decimals is not None else 2,
        displayed_present=overall_present,
        displayed_total=overall_total,
    )
    return {"source": "interactive"}, subjects, overall


def render_markdown_report(
    meta: dict[str, Any],
    subjects: list[SubjectRecord],
    overall: OverallRecord,
) -> str:
    """Produce a Markdown comparison & discrepancy evidence report."""
    lines: list[str] = [
        "# Attendance Consistency Evidence Report",
        "",
        f"- **Account / Observation Note:** {meta.get('observation_note', 'Manually recorded from own student view')}",
        f"- **Observed At:** {meta.get('observed_at', 'Not specified')}",
        f"- **Subjects Recorded:** {len(subjects)}",
        "",
        "## 1. Subject-Wise Comparison",
        "",
        "| Subject | Present | Total Held | Excused | Displayed % | Standard (`P/T`, half_up) | Standard (`P/T`, floor) | Matching Variant(s) | Closest Delta | Logic Notes |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |",
    ]

    for s in subjects:
        results = evaluate_subject(s)
        anomalies = validate_subject_logic(s)
        matches, closest = find_matching_variants(s.displayed_pct, s.displayed_decimals, results)

        std = results[0]
        std_hu = f"{std.rounded['half_up']}%" if std.exact_pct is not None else "N/A"
        std_fl = f"{std.rounded['floor']}%" if std.exact_pct is not None else "N/A"
        disp_str = f"{s.displayed_pct:.{s.displayed_decimals}f}%" if s.displayed_pct is not None else "N/A"
        match_str = "; ".join(matches) if matches else "**NO EXACT MATCH**"
        delta_str = f"{closest[2]:+}%" if closest is not None else "N/A"
        note_str = "; ".join(anomalies) if anomalies else (s.notes or "OK")

        lines.append(
            f"| {s.name} | {s.present} | {s.total_held} | {s.excused} | {disp_str} | {std_hu} | {std_fl} | {match_str} | {delta_str} | {note_str} |"
        )

    lines.extend(["", "## 2. Candidate Formula Breakdown per Subject", ""])
    for s in subjects:
        results = evaluate_subject(s)
        lines.append(f"### {s.name}")
        if s.displayed_pct is not None:
            lines.append(f"- **Displayed:** `{s.displayed_pct:.{s.displayed_decimals}f}%`")
        for res in results:
            if res.exact_pct is None:
                lines.append(f"- `{res.name}`: invalid denominator ({res.denominator})")
                continue
            variants = ", ".join(f"{k}={v}%" for k, v in res.rounded.items())
            lines.append(
                f"- `{res.name}` = `{res.numerator}/{res.denominator}` = `{res.exact_pct:.6f}%` ({variants})"
            )
        lines.append("")

    overall_results, overall_anomalies = evaluate_overall(subjects, overall)
    lines.extend(["## 3. Overall Aggregation Comparison", ""])
    if overall.displayed_pct is not None:
        lines.append(
            f"- **Displayed Overall:** `{overall.displayed_pct:.{overall.displayed_decimals}f}%`"
        )
    if overall_anomalies:
        for item in overall_anomalies:
            lines.append(f"- **Anomaly:** {item}")

    overall_matches, overall_closest = find_matching_variants(
        overall.displayed_pct, overall.displayed_decimals, overall_results
    )
    lines.extend(
        [
            "",
            "| Aggregation Method | Exact % | half_up | half_even | floor | ceil |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for res in overall_results:
        if res.exact_pct is None:
            lines.append(f"| {res.name} | N/A | N/A | N/A | N/A | N/A |")
            continue
        lines.append(
            f"| {res.name} | {res.exact_pct:.4f}% | {res.rounded['half_up']}% | "
            f"{res.rounded['half_even']}% | {res.rounded['floor']}% | {res.rounded['ceil']}% |"
        )

    lines.append("")
    if overall.displayed_pct is not None:
        if overall_matches:
            lines.append(f"**Overall Matching Formula(s):** {'; '.join(overall_matches)}")
        else:
            lines.append("**Overall Matching Formula(s):** **NONE** (discrepancy detected)")
        if overall_closest is not None:
            lines.append(
                f"**Closest Overall Match:** `{overall_closest[0]}` (`{overall_closest[1]}`), delta `{overall_closest[2]:+}%`"
            )

    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Compare manually recorded attendance counts against calculation/rounding methods."
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path to JSON file containing manually recorded subjects and overall figures.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional output path to write the Markdown evidence report.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    if args.input:
        meta, subjects, overall = load_from_json(args.input)
    else:
        meta, subjects, overall = interactive_entry()

    report = render_markdown_report(meta, subjects, overall)
    if args.report:
        args.report.write_text(report, encoding="utf-8")
        print(f"Evidence report written to {args.report}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
