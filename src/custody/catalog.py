"""Data catalog and classification.

Loads catalog.yaml: a list of datasets, each with an id, a data_class
drawn from the ordered enum synthetic < deidentified < limited_data_set
< identified, and a source. Two source kinds exist: `file` (a path and
a format, csv or parquet -- the only kind in v0.1) and `fhir` (a base
URL and an allowlist of resource types, see custody.connectors.fhir and
docs/fhir-connector.md). Optional column-level tags (for example mrn:
direct_identifier) live alongside a file-backed entry.

A dataset id that is not in the catalog classifies as `identified`, the
most restrictive class, not the least. This is the catalog's half of
"deny by default"; the other half lives in custody.policy. Both source
kinds share this one classification path deliberately: a policy rule
written against a dataset id does not need to know or care whether that
id resolves to a local file or a FHIR search, custody.gateway.Gateway
and custody.policy are unmodified by the fhir source kind existing.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DataClass(StrEnum):
    """Sensitivity of a dataset or a result derived from one.

    Ordered least to most sensitive. Comparison operators compare rank,
    not string value, so `DataClass.synthetic < DataClass.identified` is
    True and policy rules can use `min_data_class` / `max_data_class`.

    All four comparisons are defined explicitly rather than relying on
    `functools.total_ordering`: this class also inherits from `str`, and
    `str` already supplies `__le__`/`__gt__`/`__ge__` that compare by
    string VALUE ("identified" < "limited_data_set" alphabetically), which
    silently wins over a partially-generated rank-based ordering. Defining
    all four here removes that trap rather than relying on method
    resolution order to sort it out.
    """

    synthetic = "synthetic"
    deidentified = "deidentified"
    limited_data_set = "limited_data_set"
    identified = "identified"

    @property
    def rank(self) -> int:
        return _RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, DataClass):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, DataClass):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, DataClass):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, DataClass):
            return NotImplemented
        return self.rank >= other.rank


_RANK: dict[DataClass, int] = {
    DataClass.synthetic: 0,
    DataClass.deidentified: 1,
    DataClass.limited_data_set: 2,
    DataClass.identified: 3,
}

#: The most restrictive class. Used as the fallback for anything the
#: catalog has no entry for.
UNKNOWN_DEFAULT = DataClass.identified


class ColumnTag(StrEnum):
    """A column-level sensitivity tag, independent of the dataset's own
    data_class (a de-identified dataset can still carry a quasi-identifier
    column worth flagging to a reviewer)."""

    direct_identifier = "direct_identifier"
    quasi_identifier = "quasi_identifier"


class DatasetFormat(StrEnum):
    csv = "csv"
    parquet = "parquet"


class SourceKind(StrEnum):
    """`file`: a local path, mountable into the sandbox (sql.query,
    shell.run). `fhir`: a remote FHIR server, queried by the fhir.search
    tool (custody.connectors.fhir); never mounted into the sandbox,
    see docs/fhir-connector.md for why that tool makes its own request
    directly rather than through custody.sandbox."""

    file = "file"
    fhir = "fhir"


class CatalogEntry(BaseModel):
    """One dataset's catalog record. `path`/`format` are required for
    `source=file` and absent for `source=fhir`; `base_url` is required
    for `source=fhir` and absent for `source=file` -- enforced below,
    not by making every field optional and hoping callers check."""

    model_config = ConfigDict(frozen=True)

    id: str
    data_class: DataClass
    source: SourceKind = SourceKind.file
    path: Path | None = None
    format: DatasetFormat | None = None
    columns: dict[str, ColumnTag] = Field(default_factory=dict)
    base_url: str | None = None
    # Which FHIR resource types (Condition, Observation, ...) this
    # entry may be searched for. Deny-by-default like model_allowlist:
    # an empty list means NO resource type is allowed, not "any type",
    # same posture as custody.policy.engine.check_model_allowlist.
    resource_types: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("dataset id must not be empty")
        return v

    @model_validator(mode="after")
    def _fields_match_source(self) -> CatalogEntry:
        if self.source == SourceKind.file:
            if self.path is None or self.format is None:
                raise ValueError(f"dataset {self.id!r}: source=file requires path and format")
            if self.base_url is not None or self.resource_types:
                raise ValueError(
                    f"dataset {self.id!r}: base_url/resource_types only apply to source=fhir"
                )
        elif self.source == SourceKind.fhir:
            if self.base_url is None:
                raise ValueError(f"dataset {self.id!r}: source=fhir requires base_url")
            if self.path is not None or self.format is not None:
                raise ValueError(f"dataset {self.id!r}: path/format only apply to source=file")
        return self


class _CatalogFile(BaseModel):
    """Shape of catalog.yaml on disk: a top-level `datasets` list."""

    datasets: list[CatalogEntry] = Field(default_factory=list)


class DuplicateDatasetIdError(ValueError):
    """Raised when catalog.yaml declares the same dataset id twice."""


class Catalog:
    """An immutable, loaded catalog. Construct with `Catalog.load(path)`,
    not directly, so every entry has gone through validation."""

    def __init__(self, entries: dict[str, CatalogEntry]) -> None:
        self._entries = entries

    @classmethod
    def load(cls, path: Path) -> Catalog:
        """Parse and validate catalog.yaml at `path`.

        Raises DuplicateDatasetIdError if two entries share an id, and
        whatever pydantic.ValidationError the underlying models raise for
        a malformed entry (bad format, bad data_class, missing field).
        """
        raw: Any = yaml.safe_load(path.read_text()) or {}
        parsed = _CatalogFile.model_validate(raw)
        catalog_dir = path.resolve().parent

        entries: dict[str, CatalogEntry] = {}
        for entry in parsed.datasets:
            if entry.id in entries:
                raise DuplicateDatasetIdError(
                    f"dataset id {entry.id!r} is declared more than once in {path}"
                )
            if entry.source == SourceKind.file and not entry.path.is_absolute():  # type: ignore[union-attr]
                # A relative path in catalog.yaml is relative to that
                # file's own directory, not to whatever the current
                # working directory happens to be when `custody` runs.
                # Otherwise `custody serve` (or the sandbox mount it
                # drives) breaks the moment it's invoked from anywhere
                # but the exact directory the catalog was written in.
                # (fhir-source entries have no path at all, see above.)
                entry = entry.model_copy(update={"path": catalog_dir / entry.path})  # type: ignore[operator]
            entries[entry.id] = entry
        return cls(entries)

    @classmethod
    def empty(cls) -> Catalog:
        """A catalog with no entries. Every dataset id classifies as
        `identified`. Useful for tests and for a policy.explain run
        against a hypothetical request with no catalog loaded."""
        return cls({})

    def get(self, dataset_id: str) -> CatalogEntry | None:
        return self._entries.get(dataset_id)

    def classify(self, dataset_id: str) -> DataClass:
        """The data class for `dataset_id`, or UNKNOWN_DEFAULT
        (`identified`) if the catalog has no entry for it."""
        entry = self._entries.get(dataset_id)
        return entry.data_class if entry is not None else UNKNOWN_DEFAULT

    def list(self) -> list[CatalogEntry]:
        return list(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, dataset_id: str) -> bool:
        return dataset_id in self._entries
