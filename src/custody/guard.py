"""Output guard: shrinks what comes back from a query over
limited_data_set or identified data to what the data class actually
permits. See docs/threat-model.md T5 for the limits of what this layer
catches and what it does not.

v0.1 implements small-cell suppression on aggregate results. Microsoft
Presidio integration (an optional, off-by-default second-line heuristic
PHI detector on free-text output) is NOT implemented in this release;
treat any mention of it elsewhere as describing a v0.1 design intent, not
a shipped feature, until ROADMAP.md says otherwise.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from custody.catalog import DataClass

DEFAULT_SMALL_CELL_MINIMUM = 11


class AggregateRow(BaseModel):
    """One row of a grouped count, the shape `sql.query` produces for a
    GROUP BY style result (docs/demo.md's cohort-by-treatment-line
    example)."""

    model_config = ConfigDict(extra="forbid")

    group: dict[str, str]
    count: int = Field(ge=0)


class GuardedAggregateRow(BaseModel):
    """`count` is None exactly when `suppressed` is True: a small cell
    is replaced, not just flagged, so a caller that forgets to check
    `suppressed` still cannot read the real number back out of this
    object."""

    model_config = ConfigDict(extra="forbid")

    group: dict[str, str]
    count: int | None
    suppressed: bool


class OutputGuard:
    def __init__(self, small_cell_minimum: int = DEFAULT_SMALL_CELL_MINIMUM) -> None:
        if small_cell_minimum < 0:
            raise ValueError("small_cell_minimum must be >= 0")
        self._minimum = small_cell_minimum

    def guard_aggregate(
        self, rows: list[AggregateRow], data_class: DataClass
    ) -> list[GuardedAggregateRow]:
        """Synthetic and de-identified data pass through unsuppressed:
        small-cell suppression exists to stop a count of 1 or 2 from
        acting as a de facto identifier when the underlying population
        is sensitive, which is not a concern below `limited_data_set`.
        """
        if data_class < DataClass.limited_data_set:
            return [
                GuardedAggregateRow(group=r.group, count=r.count, suppressed=False) for r in rows
            ]
        return [
            GuardedAggregateRow(group=r.group, count=r.count, suppressed=False)
            if r.count >= self._minimum
            else GuardedAggregateRow(group=r.group, count=None, suppressed=True)
            for r in rows
        ]
