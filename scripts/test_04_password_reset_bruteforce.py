#!/usr/bin/env python3
"""VL-04 regression: unthrottled security-question password reset.

Sends a burst of deliberately-wrong security answers to /rest/user/reset-password and
checks whether the server ever throttles (HTTP 429). A patched app rate-limits the
endpoint; a vulnerable app accepts an unbounded number of guesses.

  Vulnerable -> every attempt returns 401 (or 200), never 429. Unlimited brute force.
  Patched    -> 429 Too Many Requests appears within the burst.
"""
import os
import common as c

EMAIL = os.environ.get("TEST_EMAIL", "testuser@local.test")
BURST = int(os.environ.get("RESET_BURST", "15"))


def test():
    wrong_answers = [f"definitely-wrong-{i}" for i in range(BURST)]
    statuses = []
    throttled_at = None
    for i, ans in enumerate(wrong_answers, 1):
        r = c.post("/rest/user/reset-password", data={
            "email": EMAIL,
            "answer": ans,
            "new": "Regression!2026",
            "repeat": "Regression!2026",
        })
        statuses.append(r.status)
        if r.status == 429:
            throttled_at = i
            break

    if throttled_at is not None:
        return c.PASS, (f"server began throttling at attempt {throttled_at} "
                        f"(HTTP 429). Statuses: {statuses}")
    return c.FAIL, (f"{len(statuses)} wrong answers accepted with no 429 throttle "
                    f"(statuses: {statuses}). Online brute force is feasible.")


if __name__ == "__main__":
    c.main("VL-04 password-reset brute force", test)
