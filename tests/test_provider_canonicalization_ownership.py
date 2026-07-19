from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

_PRIVATE_MODULE = "systeme_local_gateway.providers._canonicalization"
_EXPECTED_HELPERS = {
    "systeme_local_gateway.providers.mcp_deployment_models": (
        "_canonical_json",
        "_require_aware",
        "_validate_sorted_unique_enum_tuple",
        "_validate_sorted_unique_string_tuple",
    ),
    "systeme_local_gateway.providers.mcp_readiness_models": (
        "_canonical_json",
        "_require_aware",
        "_validate_sorted_unique_enum_tuple",
        "_validate_sorted_unique_string_tuple",
    ),
    "systeme_local_gateway.providers.mcp_operator_evidence_models": (
        "_canonical_json",
        "_require_aware",
        "_validate_sorted_unique_enum_tuple",
    ),
}


@pytest.mark.parametrize(
    ("module_name", "helper_names"),
    sorted(_EXPECTED_HELPERS.items()),
)
def test_mcp_model_modules_delegate_to_private_canonicalization(
    module_name: str,
    helper_names: tuple[str, ...],
) -> None:
    private = importlib.import_module(_PRIVATE_MODULE)
    module = importlib.import_module(module_name)

    for helper_name in helper_names:
        assert getattr(module, helper_name) is getattr(private, helper_name)

    module_path = Path(module.__file__).resolve()
    tree = ast.parse(
        module_path.read_text(encoding="utf-8"),
        filename=str(module_path),
    )
    local_functions = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert local_functions.isdisjoint(helper_names)


def test_private_canonicalization_is_not_a_public_facade_export() -> None:
    facade = importlib.import_module("systeme_local_gateway.providers")
    private = importlib.import_module(_PRIVATE_MODULE)

    assert "_canonicalization" not in facade.__all__
    for helper_name in (
        "_canonical_json",
        "_require_aware",
        "_validate_sorted_unique_enum_tuple",
        "_validate_sorted_unique_string_tuple",
    ):
        assert helper_name not in facade.__all__
        assert getattr(private, helper_name).__module__ == _PRIVATE_MODULE
