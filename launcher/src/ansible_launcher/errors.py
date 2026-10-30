"""User-facing exceptions: never embed secret contents."""


class LauncherError(Exception):
    """Configuration, security or execution error."""


class DecryptionError(LauncherError):
    """Wrong RSA key, wrong purpose, or corrupt encrypted data."""
