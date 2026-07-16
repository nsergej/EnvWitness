"""Typed errors exposed by the EnvWitness domain and application layers."""


class EnvWitnessError(Exception):
    """Base class for errors that can be presented safely to an operator."""


class ConfigurationError(EnvWitnessError):
    """Raised when configuration is missing, invalid, or unsafe."""


class CaptureError(EnvWitnessError):
    """Raised when evidence collection cannot complete safely."""


class CapsuleFormatError(EnvWitnessError):
    """Raised when a capsule is malformed, unsafe, or unsupported."""


class IntegrityError(CapsuleFormatError):
    """Raised when capsule content does not match its integrity digest."""


class PluginError(EnvWitnessError):
    """Raised when an explicitly enabled collector plugin violates its contract."""


class UpdateError(EnvWitnessError):
    """Raised when an update check or installation cannot complete."""
