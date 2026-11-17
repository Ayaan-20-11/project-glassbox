import unittest
from decimal import Decimal

from attendance_analyzer import (
    OverallRecord,
    SubjectRecord,
    evaluate_overall,
    evaluate_subject,
    find_matching_variants,
    render_markdown_report,
    validate_subject_logic,
)


class AttendanceAnalyzerTests(unittest.TestCase):
    def test_rounding_variants_and_match(self) -> None:
        rec = SubjectRecord(
            name="DSA",
            present=18,
            total_held=23,
            displayed_pct=78.26,
            displayed_decimals=2,
        )
        results = evaluate_subject(rec)
        matches, closest = find_matching_variants(rec.displayed_pct, rec.displayed_decimals, results)
        self.assertTrue(any("half_up" in m for m in matches))
        self.assertIsNotNone(closest)
        self.assertEqual(closest[2], Decimal("0.00"))

    def test_excused_variants(self) -> None:
        rec = SubjectRecord(
            name="OS",
            present=15,
            total_held=20,
            excused=2,
            displayed_pct=83.33,
            displayed_decimals=2,
        )
        results = evaluate_subject(rec)
        matches, _ = find_matching_variants(rec.displayed_pct, rec.displayed_decimals, results)
        self.assertTrue(any("total_held - excused" in m for m in matches))

    def test_logic_validation_flags_contradiction(self) -> None:
        rec = SubjectRecord(
            name="DBMS",
            present=10,
            total_held=12,
            absent=5,
        )
        anomalies = validate_subject_logic(rec)
        self.assertTrue(any("!=" in a for a in anomalies))

    def test_overall_pooled_vs_mean_and_count_mismatch(self) -> None:
        subjects = [
            SubjectRecord(name="S1", present=9, total_held=10, displayed_pct=90.0),
            SubjectRecord(name="S2", present=1, total_held=2, displayed_pct=50.0),
        ]
        overall = OverallRecord(displayed_pct=70.0, displayed_decimals=2, displayed_present=11, displayed_total=12)
        results, anomalies = evaluate_overall(subjects, overall)
        self.assertTrue(any("displayed_present" in a for a in anomalies))
        matches, _ = find_matching_variants(overall.displayed_pct, overall.displayed_decimals, results)
        self.assertTrue(any("Unweighted mean" in m for m in matches))

    def test_markdown_report_renders(self) -> None:
        subjects = [SubjectRecord(name="Math", present=7, total_held=9, displayed_pct=77.77)]
        overall = OverallRecord(displayed_pct=77.77, displayed_decimals=2)
        md = render_markdown_report({"observed_at": "test"}, subjects, overall)
        self.assertIn("# Attendance Consistency Evidence Report", md)
        self.assertIn("Math", md)


if __name__ == "__main__":
    unittest.main()
