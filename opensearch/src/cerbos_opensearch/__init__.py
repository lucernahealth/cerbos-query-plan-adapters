import importlib.metadata

from cerbos_opensearch.query import get_query

__version__ = importlib.metadata.version(__package__ or __name__)

__all__ = ["get_query"]
