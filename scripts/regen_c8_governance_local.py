"""Regenerate C8 governance JSON from the current (revalidated) C7 profile.

This is a local maintenance helper used to refresh the C8 official-work
revalidation and live-work policy after the C7 evidence window is renewed.
It mirrors the in-repo builders in ``systeme_local_gateway.c8_governance`` and
writes the canonical JSON back to ``governance/``.

Run from the repository root, after refreshing ``C7_REVIEWED_AT`` and
regenerating ``governance/c7-chatgpt-work-capability-profile.json``:

    python scripts/regen_c8_governance_local.py
"""

from __future__ import annotations

from pathlib import Path

from systeme_local_gateway import c8_governance as c8

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    revalidation = c8.build_current_c8_revalidation(ROOT)
    policy = c8.build_current_c8_policy(ROOT)

    revalidation_path = ROOT / c8.C8_REVALIDATION_PATH
    policy_path = ROOT / c8.C8_POLICY_PATH

    revalidation_path.write_text(c8.rendered_json(revalidation), encoding="utf-8", newline="\n")
    policy_path.write_text(c8.rendered_json(policy), encoding="utf-8", newline="\n")

    print(f"wrote {revalidation_path}")
    print(f"wrote {policy_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
