from __future__ import annotations

import pytest

from custody.catalog import DataClass
from custody.guard import AggregateRow, OutputGuard


class TestSmallCellSuppression:
    def test_synthetic_data_never_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=1)]
        result = guard.guard_aggregate(rows, DataClass.synthetic)
        assert result[0].suppressed is False
        assert result[0].count == 1

    def test_deidentified_data_never_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=1)]
        result = guard.guard_aggregate(rows, DataClass.deidentified)
        assert result[0].suppressed is False

    def test_identified_small_cell_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=3)]
        result = guard.guard_aggregate(rows, DataClass.identified)
        assert result[0].suppressed is True
        assert result[0].count is None

    def test_identified_large_cell_not_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=42)]
        result = guard.guard_aggregate(rows, DataClass.identified)
        assert result[0].suppressed is False
        assert result[0].count == 42

    def test_limited_data_set_also_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=2)]
        result = guard.guard_aggregate(rows, DataClass.limited_data_set)
        assert result[0].suppressed is True

    def test_count_exactly_at_minimum_is_not_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=11)]
        result = guard.guard_aggregate(rows, DataClass.identified)
        assert result[0].suppressed is False

    def test_count_one_below_minimum_is_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=10)]
        result = guard.guard_aggregate(rows, DataClass.identified)
        assert result[0].suppressed is True

    def test_mixed_rows_suppress_independently(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [
            AggregateRow(group={"line": "1L"}, count=50),
            AggregateRow(group={"line": "2L"}, count=4),
        ]
        result = guard.guard_aggregate(rows, DataClass.identified)
        assert result[0].suppressed is False
        assert result[1].suppressed is True

    def test_configurable_minimum(self) -> None:
        guard = OutputGuard(small_cell_minimum=5)
        rows = [AggregateRow(group={"line": "1L"}, count=6)]
        result = guard.guard_aggregate(rows, DataClass.identified)
        assert result[0].suppressed is False

    def test_negative_minimum_rejected(self) -> None:
        with pytest.raises(ValueError, match="small_cell_minimum"):
            OutputGuard(small_cell_minimum=-1)

    def test_zero_count_can_be_suppressed(self) -> None:
        guard = OutputGuard(small_cell_minimum=11)
        rows = [AggregateRow(group={"line": "1L"}, count=0)]
        result = guard.guard_aggregate(rows, DataClass.identified)
        assert result[0].suppressed is True

    def test_negative_count_rejected_by_model(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 - pydantic.ValidationError
            AggregateRow(group={}, count=-1)
