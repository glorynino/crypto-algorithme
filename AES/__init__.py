"""AES-128 Cipher Package."""

try:
    from cipher import AES128
except ImportError:
    from .cipher import AES128

__all__ = ['AES128']
__version__ = '1.0.0'
