import json
import unittest

from argus_core import S3StatisticsError, S3StatisticsLibrary


class S3StatisticsLibraryTests(unittest.TestCase):
    def test_tc45_bh_correction_changes_naive_per_point_decision(self) -> None:
        p_values = [0.04] + [0.9] * 19

        result = S3StatisticsLibrary.benjamini_hochberg(p_values, alpha=0.05)

        self.assertEqual(result.method, "benjamini-hochberg")
        self.assertEqual(result.alpha, 0.05)
        self.assertEqual(result.rejected.count(True), 0)
        self.assertTrue(result.naive_rejected[0])
        self.assertFalse(result.rejected[0])
        self.assertTrue(result.corrected_decision_differs_from_naive)
        self.assertAlmostEqual(result.thresholds[0], 0.0025)
        self.assertEqual(json.loads(json.dumps(result.as_payload()))["test_case"], "S3-TC45")

    def test_seeded_bootstrap_ci_and_tolerance_payloads_are_deterministic(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0, 10.0]

        first = S3StatisticsLibrary.bootstrap_ci(values, seed=1729, resamples=200)
        second = S3StatisticsLibrary.bootstrap_ci(values, seed=1729, resamples=200)
        other_seed = S3StatisticsLibrary.bootstrap_ci(values, seed=1730, resamples=200)

        self.assertEqual(first, second)
        self.assertNotEqual(first.samples_digest, other_seed.samples_digest)
        self.assertEqual(first.seed, 1729)
        self.assertEqual(first.resamples, 200)
        self.assertLessEqual(first.lower, first.estimate)
        self.assertGreaterEqual(first.upper, first.estimate)
        self.assertEqual(json.loads(json.dumps(first.as_payload()))["method"], "percentile-bootstrap")

        passed = S3StatisticsLibrary.tolerance(
            observed=10.08,
            expected=10.0,
            absolute_tolerance=0.1,
            relative_tolerance=0.02,
        )
        failed = S3StatisticsLibrary.tolerance(
            observed=10.25,
            expected=10.0,
            absolute_tolerance=0.1,
            relative_tolerance=0.02,
        )

        self.assertTrue(passed.passed)
        self.assertFalse(failed.passed)
        self.assertEqual(passed.tolerance, 0.2)
        self.assertEqual(json.loads(json.dumps(passed.as_payload()))["tolerance_policy"], "max(abs, rel*scale)")

    def test_chi_square_z_agreement_and_calibration_statistics(self) -> None:
        agreement = S3StatisticsLibrary.chi_square_z_agreement(
            observed=[1.0, 2.0, 3.1],
            expected=[1.0, 2.0, 3.0],
            observed_uncertainty=[0.2, 0.2, 0.2],
            expected_uncertainty=[0.0, 0.0, 0.0],
            max_abs_z=2.0,
            max_reduced_chi_square=2.0,
            alpha=0.05,
        )

        self.assertTrue(agreement.passed)
        self.assertEqual(agreement.dof, 3)
        self.assertAlmostEqual(agreement.z_scores[2], 0.5)
        self.assertLess(agreement.reduced_chi_square, 1.0)
        self.assertGreaterEqual(agreement.p_value, 0.05)

        coverage = S3StatisticsLibrary.coverage(
            truth=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            lower=[-1, 0, 1, 2, 3, 4, 5, 6, 20, 20],
            upper=[1, 2, 3, 4, 5, 6, 7, 8, 21, 21],
            nominal_coverage=0.8,
            tolerance=0.05,
        )
        self.assertTrue(coverage.passed)
        self.assertEqual(coverage.covered_count, 8)
        self.assertAlmostEqual(coverage.empirical_coverage, 0.8)

        pit = S3StatisticsLibrary.pit_uniformity(
            [0.05, 0.14, 0.22, 0.31, 0.43, 0.56, 0.67, 0.76, 0.87, 0.96],
            alpha=0.05,
        )
        self.assertTrue(pit.passed)
        self.assertLess(pit.ks_statistic, 0.2)
        self.assertGreaterEqual(pit.p_value, 0.05)

    def test_false_positive_rate_bound_is_fail_closed_and_json_safe(self) -> None:
        clean = S3StatisticsLibrary.false_positive_rate_bound(
            false_positives=0,
            trials=100,
            confidence_level=0.95,
            max_rate=0.05,
        )
        noisy = S3StatisticsLibrary.false_positive_rate_bound(
            false_positives=3,
            trials=100,
            confidence_level=0.95,
            max_rate=0.02,
        )

        self.assertTrue(clean.passed)
        self.assertLess(clean.upper_bound, 0.05)
        self.assertFalse(noisy.passed)
        self.assertGreater(noisy.upper_bound, 0.02)
        self.assertEqual(json.loads(json.dumps(noisy.as_payload()))["method"], "exact-binomial-one-sided")

        with self.assertRaises(S3StatisticsError) as raised:
            S3StatisticsLibrary.false_positive_rate_bound(false_positives=2, trials=1)
        self.assertEqual(raised.exception.code, "STAT_INVALID_COUNTS")


if __name__ == "__main__":
    unittest.main()
