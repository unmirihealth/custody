"""Generates a synthetic tumor registry, fixed seed so the demo is
reproducible. Every value is generated; nothing here is drawn from a
real dataset, see CONTRIBUTING.md. File names and the data itself are
marked "synthetic" throughout, not just in a README note.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

SEED = 20261020

_SITES = ["lung", "breast", "colon", "pancreas"]
_HISTOLOGIES = ["adenocarcinoma", "squamous cell carcinoma", "large cell carcinoma"]
_STAGES = ["I", "II", "III", "IV"]
_STATUS = ["positive", "negative"]
_PDL1 = ["high", "low", "negative"]
_TREATMENT_LINES = ["1L", "2L", "3L+"]
_VITAL = ["alive", "deceased"]

_FIRST_NAMES = ["Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Avery"]
_LAST_NAMES = ["Rivera", "Chen", "Patel", "Nguyen", "Kowalski", "Osei", "Haddad", "Silva"]


def generate_tumor_registry(n: int = 5000, seed: int = SEED) -> list[dict[str, str]]:
    """De-identified rows: no MRN, no name, no exact dates finer than a
    year-month, matching what a real de-identification process would
    leave behind."""
    rng = random.Random(seed)  # noqa: S311 - synthetic data generation, not crypto
    rows = []
    for i in range(n):
        rows.append(
            {
                "patient_id": f"SYN-{i:06d}",
                "primary_site": rng.choice(_SITES),
                "histology": rng.choice(_HISTOLOGIES),
                "stage": rng.choice(_STAGES),
                "diagnosis_year_month": f"20{rng.randint(20, 26)}-{rng.randint(1, 12):02d}",
                "egfr_status": rng.choice(_STATUS),
                "alk_status": rng.choice(_STATUS),
                "kras_status": rng.choice(_STATUS),
                "her2_status": rng.choice(_STATUS),
                "pdl1_status": rng.choice(_PDL1),
                "treatment_line": rng.choice(_TREATMENT_LINES),
                "vital_status": rng.choice(_VITAL),
            }
        )
    return rows


def add_fake_identifiers(
    rows: list[dict[str, str]], seed: int = SEED + 1
) -> list[dict[str, str]]:
    """The same rows, with a generated (clearly fake) MRN and name
    column added, for the identified-data branch of the demo."""
    rng = random.Random(seed)  # noqa: S311 - synthetic data generation, not crypto
    out = []
    for row in rows:
        out.append(
            {
                **row,
                "mrn": f"SYN-MRN-{rng.randint(100000, 999999)}",
                "patient_name": f"{rng.choice(_FIRST_NAMES)} {rng.choice(_LAST_NAMES)}",
            }
        )
    return out


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
