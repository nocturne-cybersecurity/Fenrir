"""Validators que confirman o rechazan findings."""

from fenrir.modules.validate.cve_lookup import CVELookupModule
from fenrir.modules.validate.cve_validation import CVEValidator

__all__ = [
    "CVEValidator",
    "CVELookupModule",
]
