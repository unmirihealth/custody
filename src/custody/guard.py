"""Output guard.

Results derived from limited_data_set or identified data are returned as
aggregates or redacted previews per policy, with small-cell suppression
(configurable minimum, default 11) applied to aggregate outputs. An
optional, off-by-default integration with Microsoft Presidio adds a
second-line heuristic PHI detector on outputs; it is documented as
heuristic, not a guarantee, see docs/threat-model.md T5.

Planned surface:
    class OutputGuard:
        def redact(self, result: QueryResult, data_class: DataClass, policy: GuardPolicy) -> QueryResult: ...

Not yet implemented.
"""

raise NotImplementedError("custody.guard is not yet implemented (v0.1 skeleton)")
