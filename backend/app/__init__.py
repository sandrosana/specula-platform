"""Specula Threat backend."""

from importlib.metadata import PackageNotFoundError, version

SERVICE_NAME = "specula-threat"

try:
    __version__ = version(SERVICE_NAME)
except PackageNotFoundError:  # running from a source tree without installing the package
    __version__ = "0.0.0"
