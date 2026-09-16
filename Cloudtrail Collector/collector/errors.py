"""Exception hierarchy.

Every failure mode in this tool gets a specific type. A partial collection that
looks complete is the worst outcome for an evidence tool, so nothing is allowed
to fail generically.
"""

from __future__ import annotations


class CollectorError(Exception):
    """Base class for all collector failures."""


class ConfigError(CollectorError):
    """Invalid or contradictory CLI configuration."""


class CredentialError(CollectorError):
    """Credentials missing, unusable, or pointing at the wrong account."""


class EnvelopeError(CollectorError):
    """A LookupEvents item could not be unwrapped into a trail-format record."""


class CopyVerificationError(CollectorError):
    """A copied object did not match its source after all retries."""


class StateError(CollectorError):
    """The on-disk resume state is unusable or inconsistent with this run."""


class UploadError(CollectorError):
    """A multipart upload could not be completed."""
