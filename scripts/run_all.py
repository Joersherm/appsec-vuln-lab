#!/usr/bin/env python3
"""Run the full regression suite and print a summary table.

Usage:
    python3 scripts/run_all.py

Honors the same env vars as the individual scripts (JUICE_URL, TEST_EMAIL,
TEST_PASSWORD, JUICE_ADMIN_TOKEN). Exit code is 0 only if no test reports VULNERABLE
(FAIL); unreachable/skipped tests do not fail the run but are flagged.
"""
import importlib
import common as c

TESTS = [
    ("VL-01 SQLi login auth bypass", "test_01_sqli_login"),
    ("VL-02 IDOR basket access", "test_02_idor_basket"),
    ("VL-03 DOM XSS in search", "test_03_dom_xss_search"),
    ("VL-04 password-reset brute force", "test_04_password_reset_bruteforce"),
    ("VL-05 /ftp null-byte bypass", "test_05_ftp_null_byte"),
    ("VL-06 unsalted MD5 password hash", "test_06_password_hash"),
]


def main():
    print(f"Target: {c.BASE_URL}\n" + "=" * 60)
    rows = []
    any_fail = False
    for name, mod_name in TESTS:
        mod = importlib.import_module(mod_name)
        code = c.run(name, mod.test)
        rows.append((name, code))
        if code == c.FAIL:
            any_fail = True

    print("=" * 60 + "\nSummary:")
    label = {c.PASS: "PASS", c.FAIL: "FAIL", c.UNREACHABLE: "SKIP"}
    for name, code in rows:
        print(f"  [{label[code]}] {name}")

    skipped = sum(1 for _, code in rows if code == c.UNREACHABLE)
    failed = sum(1 for _, code in rows if code == c.FAIL)
    passed = sum(1 for _, code in rows if code == c.PASS)
    print(f"\n{passed} passed, {failed} vulnerable, {skipped} skipped.")
    return 1 if any_fail else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
