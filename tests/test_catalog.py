from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from custody.catalog import (
    Catalog,
    ColumnTag,
    DataClass,
    DuplicateDatasetIdError,
)


class TestDataClassOrdering:
    def test_full_order(self) -> None:
        assert (
            DataClass.synthetic
            < DataClass.deidentified
            < DataClass.limited_data_set
            < DataClass.identified
        )

    def test_equal_not_less_than(self) -> None:
        assert not (DataClass.identified < DataClass.identified)

    def test_le_ge(self) -> None:
        assert DataClass.synthetic <= DataClass.synthetic
        assert DataClass.identified >= DataClass.limited_data_set

    def test_sortable(self) -> None:
        shuffled = [
            DataClass.identified,
            DataClass.synthetic,
            DataClass.limited_data_set,
            DataClass.deidentified,
        ]
        assert sorted(shuffled) == [
            DataClass.synthetic,
            DataClass.deidentified,
            DataClass.limited_data_set,
            DataClass.identified,
        ]


class TestCatalogLoad:
    def test_loads_all_entries(self, fixtures_dir: Path) -> None:
        cat = Catalog.load(fixtures_dir / "catalog.yaml")
        assert len(cat) == 3
        assert "tumor_registry_deid" in cat

    def test_classify_known_dataset(self, fixtures_dir: Path) -> None:
        cat = Catalog.load(fixtures_dir / "catalog.yaml")
        assert cat.classify("tumor_registry_deid") == DataClass.deidentified
        assert cat.classify("tumor_registry_identified") == DataClass.identified
        assert cat.classify("cohort_summary_synthetic") == DataClass.synthetic

    def test_unknown_dataset_classifies_as_identified(self, fixtures_dir: Path) -> None:
        """Deny-by-default: an id the catalog has never heard of is the
        most restrictive class, not the least."""
        cat = Catalog.load(fixtures_dir / "catalog.yaml")
        assert cat.classify("something_nobody_declared") == DataClass.identified

    def test_column_tags(self, fixtures_dir: Path) -> None:
        cat = Catalog.load(fixtures_dir / "catalog.yaml")
        entry = cat.get("tumor_registry_identified")
        assert entry is not None
        assert entry.columns["mrn"] == ColumnTag.direct_identifier
        assert entry.columns["zip_code"] == ColumnTag.quasi_identifier

    def test_empty_catalog_classifies_everything_as_identified(self) -> None:
        cat = Catalog.empty()
        assert cat.classify("anything") == DataClass.identified
        assert cat.list() == []

    def test_duplicate_id_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "catalog.yaml"
        bad.write_text(
            """
datasets:
  - id: dupe
    path: a.csv
    format: csv
    data_class: synthetic
  - id: dupe
    path: b.csv
    format: csv
    data_class: identified
"""
        )
        with pytest.raises(DuplicateDatasetIdError):
            Catalog.load(bad)

    def test_bad_format_raises_validation_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "catalog.yaml"
        bad.write_text(
            """
datasets:
  - id: x
    path: a.xlsx
    format: xlsx
    data_class: synthetic
"""
        )
        with pytest.raises(ValidationError):
            Catalog.load(bad)

    def test_bad_data_class_raises_validation_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "catalog.yaml"
        bad.write_text(
            """
datasets:
  - id: x
    path: a.csv
    format: csv
    data_class: top_secret
"""
        )
        with pytest.raises(ValidationError):
            Catalog.load(bad)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            Catalog.load(tmp_path / "does_not_exist.yaml")

    def test_empty_file_is_empty_catalog(self, tmp_path: Path) -> None:
        empty = tmp_path / "catalog.yaml"
        empty.write_text("")
        cat = Catalog.load(empty)
        assert len(cat) == 0


class TestComparisonAgainstOtherTypes:
    def test_lt_against_non_dataclass_is_not_implemented(self) -> None:
        assert DataClass.synthetic.__lt__("not a DataClass") is NotImplemented

    def test_le_against_non_dataclass_is_not_implemented(self) -> None:
        assert DataClass.synthetic.__le__(3) is NotImplemented

    def test_gt_against_non_dataclass_is_not_implemented(self) -> None:
        assert DataClass.synthetic.__gt__(3) is NotImplemented

    def test_ge_against_non_dataclass_is_not_implemented(self) -> None:
        assert DataClass.synthetic.__ge__(3) is NotImplemented


class TestEmptyId:
    def test_empty_dataset_id_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "catalog.yaml"
        bad.write_text(
            """
datasets:
  - id: "  "
    path: a.csv
    format: csv
    data_class: synthetic
"""
        )
        with pytest.raises(ValidationError):
            Catalog.load(bad)


class TestRelativePathResolution:
    def test_relative_path_resolved_against_catalog_file_directory(
        self, tmp_path: Path
    ) -> None:
        """A relative `path` in catalog.yaml must not depend on the
        process's current working directory, otherwise mounting it into
        the sandbox breaks the moment custody is run from anywhere but
        the exact directory the catalog was authored in."""
        deployment_dir = tmp_path / "some" / "nested" / "deployment"
        deployment_dir.mkdir(parents=True)
        (deployment_dir / "data").mkdir()
        (deployment_dir / "data" / "a.csv").write_text("x\n1\n")

        catalog_path = deployment_dir / "catalog.yaml"
        catalog_path.write_text(
            "datasets:\n"
            "  - id: a\n"
            "    path: data/a.csv\n"
            "    format: csv\n"
            "    data_class: synthetic\n"
        )

        cat = Catalog.load(catalog_path)
        entry = cat.get("a")
        assert entry is not None
        assert entry.path == deployment_dir / "data" / "a.csv"
        assert entry.path.is_absolute()

    def test_absolute_path_left_unchanged(self, tmp_path: Path) -> None:
        data_file = tmp_path / "somewhere_else" / "a.csv"
        data_file.parent.mkdir(parents=True)
        data_file.write_text("x\n1\n")

        catalog_dir = tmp_path / "deployment"
        catalog_dir.mkdir()
        catalog_path = catalog_dir / "catalog.yaml"
        catalog_path.write_text(
            f"datasets:\n"
            f"  - id: a\n"
            f"    path: {data_file}\n"
            f"    format: csv\n"
            f"    data_class: synthetic\n"
        )

        cat = Catalog.load(catalog_path)
        entry = cat.get("a")
        assert entry is not None
        assert entry.path == data_file
