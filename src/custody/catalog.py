"""Data catalog and classification.

Loads catalog.yaml: a list of datasets, each with an id, a path, a format
(csv or parquet), and a data_class drawn from the ordered enum synthetic
< deidentified < limited_data_set < identified. Optional column-level tags
(for example mrn: direct_identifier) live alongside a dataset's entry.

An unlabeled dataset, or a dataset referenced in a tool call but absent
from the catalog, is treated as identified: the most restrictive class,
not the least. This is the catalog's half of "deny by default"; the other
half lives in custody.policy.

Planned surface:
    class DataClass(StrEnum): ...        # ordered, comparable
    class ColumnTag(StrEnum): ...
    class CatalogEntry(BaseModel): ...
    class Catalog:
        @classmethod
        def load(cls, path: Path) -> "Catalog": ...
        def classify(self, dataset_id: str) -> DataClass: ...
        def list(self) -> list[CatalogEntry]: ...

Not yet implemented. This module is a placeholder showing the planned
shape; see the build plan in the project's tracking issue before writing
against it.
"""

from __future__ import annotations

raise NotImplementedError("custody.catalog is not yet implemented (v0.1 skeleton)")
