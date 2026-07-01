from __future__ import annotations

import unittest

from argus_core import BLAKE3_PREFIX, canonical_json_bytes, hash_bytes, hash_json


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_is_key_order_stable(self) -> None:
        left = canonical_json_bytes({"b": 2, "a": {"d": 4, "c": 3}})
        right = canonical_json_bytes({"a": {"c": 3, "d": 4}, "b": 2})

        self.assertEqual(left, right)
        self.assertEqual(left, b'{"a":{"c":3,"d":4},"b":2}')


class Blake3HashTests(unittest.TestCase):
    def test_hash_bytes_uses_c4_prefix_and_known_blake3_vector(self) -> None:
        self.assertEqual(
            hash_bytes(b""),
            f"{BLAKE3_PREFIX}af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )

    def test_hash_json_is_key_order_stable(self) -> None:
        left = hash_json({"b": 2, "a": 1})
        right = hash_json({"a": 1, "b": 2})

        self.assertEqual(left, right)
        self.assertTrue(left.startswith(BLAKE3_PREFIX))


if __name__ == "__main__":
    unittest.main()
