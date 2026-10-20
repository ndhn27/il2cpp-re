# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ndhn27

"""Tests for the header validator (Python controller + JS agent copy).

Run from the repo root:  python -m unittest discover -s tests -v
Headers here are synthetic, built from the Il2CppDumper layout - they exercise the checks, they
are NOT samples from a real app.
"""
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import dump_clean_header as d  # noqa: E402  (frida is only imported inside main())

AGENT = os.path.join(ROOT, "agents", "dump_clean_header_v4.js")
DUMP_SIZE = 1024


def build_header(layout=24.2, version=None, size=DUMP_SIZE):
    """A well-formed header: tables laid out back to back right after the struct."""
    version = int(layout) if version is None else version
    fields = d._fields_for(layout if layout <= d.KNOWN_VERSION_MAX else d.KNOWN_VERSION_MAX)
    words = [0] * (d.MIN_HEADER_SIZE // 4)
    words[0] = d.REAL_MAGIC
    words[1] = version
    off = len(fields) * 4
    for i in range(2, len(fields), 2):
        name = fields[i + 1][0]
        if name == "windowsRuntimeTypeNamesSize":      # an empty table, as in most apps
            words[i], words[i + 1] = off, 0
        elif name.endswith("Size"):
            words[i], words[i + 1] = off, 1000 + i * 8
            off += 1000 + i * 8
        else:                                           # *Count: element size unknown, leave room
            words[i], words[i + 1] = off, 10
            off += 80
    raw = struct.pack("<" + "I" * len(words), *[w & 0xFFFFFFFF for w in words])
    return bytearray(raw + bytes(size - len(raw)))


def put(buf, field_name, value, layout=24.2):
    idx = [f[0] for f in d._fields_for(layout)].index(field_name)
    struct.pack_into("<i", buf, idx * 4, value)


def get(buf, field_name, layout=24.2):
    idx = [f[0] for f in d._fields_for(layout)].index(field_name)
    return struct.unpack_from("<i", buf, idx * 4)[0]


LAYOUTS = [16, 17, 18, 19, 20, 21, 22, 23, 24, 24.2, 25, 26, 27, 28, 29, 30, 31]


class ValidHeaders(unittest.TestCase):
    def test_every_known_layout_passes(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                res = d.validate_header(bytes(build_header(layout)))
                self.assertTrue(res.ok, res.errors)
                self.assertEqual(res.warnings, [])
                self.assertEqual(res.layout, float(layout))
                self.assertEqual(res.header_bytes, len(d._fields_for(layout)) * 4)

    def test_v24_variants_are_told_apart_by_first_table_offset(self):
        self.assertEqual(d.validate_header(bytes(build_header(24))).header_bytes, 272)
        self.assertEqual(d.validate_header(bytes(build_header(24.2))).header_bytes, 264)

    def test_trailing_bytes_after_the_struct_are_ignored(self):
        buf = build_header(29)
        buf[300:] = bytes(random.Random(1).randrange(256) for _ in range(len(buf) - 300))
        self.assertTrue(d.validate_header(bytes(buf)).ok)

    def test_newer_version_is_accepted_with_a_warning(self):
        res = d.validate_header(bytes(build_header(31, version=33)))
        self.assertTrue(res.ok, res.errors)
        self.assertTrue(any("newer than the known layouts" in w for w in res.warnings))


class RejectedHeaders(unittest.TestCase):
    def test_magic_alone_is_not_enough(self):
        buf = bytearray(DUMP_SIZE)
        struct.pack_into("<I", buf, 0, d.REAL_MAGIC)
        res = d.validate_header(bytes(buf))
        self.assertFalse(res.ok)
        buf = bytearray(random.Random(2).randrange(256) for _ in range(DUMP_SIZE))
        struct.pack_into("<II", buf, 0, d.REAL_MAGIC, 24)
        self.assertFalse(d.validate_header(bytes(buf)).ok)

    def test_magic_plus_version_alone_is_not_enough(self):
        buf = bytearray(DUMP_SIZE)
        struct.pack_into("<II", buf, 0, d.REAL_MAGIC, 29)
        res = d.validate_header(bytes(buf))
        self.assertFalse(res.ok)
        self.assertTrue(any("every real app has this table" in e for e in res.errors))

    def test_wrong_magic(self):
        buf = build_header()
        struct.pack_into("<I", buf, 0, 0x12345678)
        res = d.validate_header(bytes(buf))
        self.assertFalse(res.ok)
        self.assertIn("magic", res.errors[0])

    def test_implausible_versions(self):
        for version in (0, 5, 15, 1001, -1):
            with self.subTest(version=version):
                res = d.validate_header(bytes(build_header(24.2, version=version)))
                self.assertFalse(res.ok)
                self.assertIn("plausible range", res.errors[0])

    def test_too_short(self):
        self.assertFalse(d.validate_header(bytes(build_header())[: d.MIN_HEADER_SIZE - 1]).ok)
        self.assertFalse(d.validate_header(b"").ok)
        self.assertFalse(d.validate_header(None).ok)

    def test_negative_field(self):
        buf = build_header()
        put(buf, "methodsSize", -4)
        res = d.validate_header(bytes(buf))
        self.assertFalse(res.ok)
        self.assertTrue(any("negative" in e for e in res.errors))

    def test_int32_overflow(self):
        buf = build_header()
        put(buf, "fieldsOffset", 0x7FFFFF00)
        put(buf, "fieldsSize", 0x1000)
        self.assertFalse(d.validate_header(bytes(buf)).ok)

    def test_overlapping_tables(self):
        buf = build_header()
        put(buf, "typeDefinitionsOffset", get(buf, "methodsOffset"))
        res = d.validate_header(bytes(buf))
        self.assertFalse(res.ok)
        self.assertTrue(any("overlaps" in e for e in res.errors))

    def test_empty_key_table(self):
        buf = build_header()
        put(buf, "typeDefinitionsSize", 0)
        self.assertFalse(d.validate_header(bytes(buf)).ok)

    def test_table_inside_header(self):
        buf = build_header()
        put(buf, "methodsOffset", 8)
        res = d.validate_header(bytes(buf))
        self.assertFalse(res.ok)
        self.assertTrue(any("inside the" in e for e in res.errors))

    def test_first_table_before_end_of_header(self):
        buf = build_header()
        put(buf, "stringLiteralOffset", 100)
        self.assertFalse(d.validate_header(bytes(buf)).ok)


class LenientAndWarnings(unittest.TestCase):
    def test_lenient_downgrades_structural_errors_only(self):
        buf = build_header()
        put(buf, "typeDefinitionsSize", 0)
        res = d.validate_header(bytes(buf), lenient=True)
        self.assertTrue(res.ok)
        self.assertTrue(any(w.startswith("(lenient)") for w in res.warnings))

    def test_lenient_still_requires_magic_and_version(self):
        buf = build_header()
        struct.pack_into("<I", buf, 0, 0)
        self.assertFalse(d.validate_header(bytes(buf), lenient=True).ok)
        self.assertFalse(d.validate_header(bytes(build_header(24.2, version=3)), lenient=True).ok)

    def test_swapped_tables_only_warn(self):
        buf = build_header()
        a = (get(buf, "methodsOffset"), get(buf, "methodsSize"))
        b = (get(buf, "typeDefinitionsOffset"), get(buf, "typeDefinitionsSize"))
        put(buf, "methodsOffset", b[0]); put(buf, "methodsSize", b[1])
        put(buf, "typeDefinitionsOffset", a[0]); put(buf, "typeDefinitionsSize", a[1])
        res = d.validate_header(bytes(buf))
        self.assertTrue(res.ok, res.errors)
        self.assertTrue(any("not ascending" in w for w in res.warnings))

    def test_big_gap_and_unexpected_first_offset_only_warn(self):
        buf = build_header(29)
        names = [f[0] for f in d._fields_for(29)]
        # padding right after the struct: every table moves back by 16 bytes
        # and a 5000-byte hole opens in front of typeDefinitions
        start_hole = names.index("typeDefinitionsOffset")
        for i in range(2, len(names), 2):
            delta = 16 + (5000 if i >= start_hole else 0)
            if struct.unpack_from("<i", buf, (i + 1) * 4)[0] > 0:
                struct.pack_into("<i", buf, i * 4, struct.unpack_from("<i", buf, i * 4)[0] + delta)
        res = d.validate_header(bytes(buf))
        self.assertTrue(res.ok, res.errors)
        self.assertTrue(any("stringLiteralOffset" in w for w in res.warnings))
        self.assertTrue(any("gap" in w for w in res.warnings))


class TableDrift(unittest.TestCase):
    def test_js_and_python_tables_match(self):
        with open(AGENT, encoding="utf-8") as f:
            src = f.read()
        match = re.search(r"const HEADER_FIELDS = (\[.*?\n\]);", src, re.S)
        self.assertIsNotNone(match, "HEADER_FIELDS not found in the agent")
        js_table = [tuple(row) for row in json.loads(match.group(1))]
        self.assertEqual(js_table, [tuple(row) for row in d.HEADER_FIELDS])


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class JsParity(unittest.TestCase):
    """The agent carries its own copy of the validator - both must reach the same verdicts."""

    def vectors(self):
        rng = random.Random(7)
        out = []
        for layout in LAYOUTS:
            out.append((build_header(layout), False))
        base = build_header(29)
        for field, value in (("methodsSize", -4), ("typeDefinitionsSize", 0), ("methodsOffset", 8),
                             ("stringLiteralOffset", 100), ("fieldsOffset", 0x7FFFFF00)):
            b = bytearray(base)
            put(b, field, value, 29)
            out.append((b, False))
            out.append((b, True))
        b = bytearray(base)
        put(b, "typeDefinitionsOffset", get(b, "methodsOffset", 29), 29)
        out.append((b, False))
        out.append((build_header(31, version=40), False))
        for version in (3, 2000):
            out.append((build_header(24.2, version=version), False))
        zero = bytearray(DUMP_SIZE)
        struct.pack_into("<II", zero, 0, d.REAL_MAGIC, 24)
        out.append((zero, False))
        for _ in range(20):
            noise = bytearray(rng.randrange(256) for _ in range(DUMP_SIZE))
            struct.pack_into("<II", noise, 0, d.REAL_MAGIC, rng.choice([24, 27, 29, 31]))
            out.append((noise, False))
            out.append((noise, True))
        out.append((bytearray(100), False))
        return out

    def test_same_verdicts(self):
        vectors = self.vectors()
        payload = json.dumps([{"hex": bytes(v).hex(), "lenient": lenient} for v, lenient in vectors])
        proc = subprocess.run(
            ["node", os.path.join(ROOT, "tests", "validate_vectors.js")],
            input=payload, capture_output=True, text=True, check=True,
        )
        js_results = json.loads(proc.stdout)
        self.assertEqual(len(js_results), len(vectors))
        for i, ((data, lenient), js) in enumerate(zip(vectors, js_results)):
            py = d.validate_header(bytes(data), lenient=lenient)
            with self.subTest(vector=i, lenient=lenient):
                self.assertEqual(js["ok"], py.ok, (js, py))
                self.assertEqual(js["layout"], py.layout)
                self.assertEqual(len(js["errors"]), len(py.errors), (js, py))
                self.assertEqual(len(js["warnings"]), len(py.warnings), (js, py))


if __name__ == "__main__":
    unittest.main()
