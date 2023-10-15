
from copy import deepcopy


def compare_schema(actual: dict, reference, message=None):
    """Compare two OpenAPI schemas, ignoring version numbers"""
    actual = deepcopy(actual)
    actual['openapi'] = reference['openapi']
    try:
        actual['info']['version'] = reference['info']['version']
    finally:
        assert actual == reference, message
