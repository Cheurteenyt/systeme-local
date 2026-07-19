from __future__ import annotations

import hashlib
import importlib
import json
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import get_origin, get_type_hints

import pytest
from pydantic import BaseModel
from pydantic_core import PydanticUndefined
import sys

FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "provider_canonicalization_compatibility_v1.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

HELPER_MODULES = (
    "systeme_local_gateway.providers._canonicalization",
    "systeme_local_gateway.providers.mcp_deployment_models",
    "systeme_local_gateway.providers.mcp_readiness_models",
    "systeme_local_gateway.providers.mcp_operator_evidence_models",
)


class ProbeEnum(StrEnum):
    A = "a"
    B = "b"


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def resolve(module_name: str, qualname: str) -> object:
    value: object = importlib.import_module(module_name)
    for segment in qualname.split("."):
        value = getattr(value, segment)
    return value


def encode_value(value: object) -> object:
    if value is PydanticUndefined:
        return {"type": "pydantic_undefined"}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, datetime):
        return {"type": "datetime", "value": value.isoformat()}
    if isinstance(value, StrEnum):
        return {
            "type": "enum",
            "module": type(value).__module__,
            "qualname": type(value).__qualname__,
            "value": value.value,
        }
    if isinstance(value, BaseModel):
        return {
            "type": "model",
            "module": type(value).__module__,
            "qualname": type(value).__qualname__,
            "data": value.model_dump(mode="json"),
        }
    if isinstance(value, Path):
        return {"type": "path", "value": value.as_posix()}
    if isinstance(value, tuple):
        return {"type": "tuple", "items": [encode_value(item) for item in value]}
    if isinstance(value, list):
        return {"type": "list", "items": [encode_value(item) for item in value]}
    if isinstance(value, frozenset):
        items = [encode_value(item) for item in value]
        items.sort(key=canonical_json)
        return {"type": "frozenset", "items": items}
    if isinstance(value, set):
        items = [encode_value(item) for item in value]
        items.sort(key=canonical_json)
        return {"type": "set", "items": items}
    if isinstance(value, dict):
        return {
            "type": "dict",
            "items": [[encode_value(key), encode_value(item)] for key, item in value.items()],
        }
    raise TypeError(
        f"unsupported compatibility value {type(value).__module__}.{type(value).__qualname__}"
    )


def decode_value(value: object) -> object:
    if not isinstance(value, dict) or "type" not in value:
        return value
    kind = value["type"]
    if kind == "bytes":
        return bytes.fromhex(value["hex"])
    if kind == "datetime":
        return datetime.fromisoformat(value["value"])
    if kind == "enum":
        enum_type = resolve(value["module"], value["qualname"])
        return enum_type(value["value"])
    if kind == "model":
        model_type = resolve(value["module"], value["qualname"])
        return model_type.model_validate(value["data"])
    if kind == "path":
        return Path(value["value"])
    if kind == "tuple":
        return tuple(decode_value(item) for item in value["items"])
    if kind == "list":
        return [decode_value(item) for item in value["items"]]
    if kind == "set":
        return {decode_value(item) for item in value["items"]}
    if kind == "frozenset":
        return frozenset(decode_value(item) for item in value["items"])
    if kind == "dict":
        return {decode_value(key): decode_value(item) for key, item in value["items"]}
    if kind == "pydantic_undefined":
        return PydanticUndefined
    raise AssertionError(f"unsupported fixture value kind: {kind}")


def decode_argument(value: object, annotation: object) -> object:
    decoded = decode_value(value)
    if (
        isinstance(decoded, str)
        and isinstance(annotation, type)
        and issubclass(annotation, StrEnum)
    ):
        return annotation(decoded)
    return decoded


def model_contract(model: type[BaseModel]) -> dict[str, object]:
    fields: list[dict[str, object]] = []
    for name, field in model.model_fields.items():
        fields.append(
            {
                "name": name,
                "alias": field.alias,
                "serialization_alias": field.serialization_alias,
                "required": field.is_required(),
                "default": encode_value(field.default),
            }
        )
    config = model.model_config
    return {
        "module": model.__module__,
        "name": model.__qualname__,
        "config": {
            "extra": config.get("extra"),
            "frozen": config.get("frozen"),
            "strict": config.get("strict"),
        },
        "fields": fields,
        "schema_sha256": canonical_sha(model.model_json_schema()),
    }


def helper_implementations(name: str) -> list[object]:
    implementations: list[object] = []
    for module_name in HELPER_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as error:
            if error.name == module_name:
                continue
            raise
        candidate = getattr(module, name, None)
        if candidate is not None:
            implementations.append(candidate)
    assert implementations, f"no implementation found for {name}"
    return implementations


class CapturingHash:
    def __init__(self, real_sha256: object, initial: bytes = b"") -> None:
        self._inner = real_sha256(initial)
        self._chunks = [bytes(initial)] if initial else []
        self._recorded = False
        self.records: list[dict[str, str]] = []

    def update(self, data: bytes) -> None:
        chunk = bytes(data)
        self._chunks.append(chunk)
        self._inner.update(chunk)

    def _record(self, digest: str) -> None:
        if self._recorded:
            return
        self.records.append(
            {
                "message_hex": b"".join(self._chunks).hex(),
                "digest": digest,
            }
        )
        self._recorded = True

    def hexdigest(self) -> str:
        result = self._inner.hexdigest()
        self._record(result)
        return result

    def digest(self) -> bytes:
        result = self._inner.digest()
        self._record(result.hex())
        return result

    def copy(self) -> "CapturingHash":
        copied = object.__new__(CapturingHash)
        copied._inner = self._inner.copy()
        copied._chunks = list(self._chunks)
        copied._recorded = self._recorded
        copied.records = self.records
        return copied


def test_fixture_is_bound_to_the_approved_baseline() -> None:
    assert FIXTURE["version"] == 1
    assert FIXTURE["base_sha"] == "c720f4ae9d295e3e2af6993b40a0b03bfd14c2b9"
    assert (
        FIXTURE["baseline_report_sha256"]
        == "D831C0056F8FDC35475BB837C2138DF15A43D164B4947C89CCBE91331C674672"
    )
    assert FIXTURE["digest_vectors"]["count"] == 13


def test_provider_facade_exports_and_object_identities_are_exact() -> None:
    facade = importlib.import_module("systeme_local_gateway.providers")
    expected = FIXTURE["provider_facade"]
    assert list(facade.__all__) == expected["exports"]
    assert len(facade.__all__) == 179

    observed_origins: list[dict[str, str]] = []
    for row in expected["origins"]:
        value = getattr(facade, row["name"])
        origin = resolve(row["module"], row["qualname"])
        if row["module"] == "typing":
            assert row["name"] == "LifecycleEvent"
            models_module = importlib.import_module("systeme_local_gateway.providers.models")
            assert value is getattr(models_module, row["name"])
            assert get_origin(value) is origin
        else:
            assert value is origin
        observed_origins.append(
            {
                "name": row["name"],
                "module": getattr(value, "__module__", type(value).__module__),
                "qualname": getattr(value, "__qualname__", type(value).__qualname__),
                "kind": type(value).__name__,
            }
        )
    assert canonical_sha(list(facade.__all__)) == expected["exports_sha256"]
    assert canonical_sha(observed_origins) == expected["origins_sha256"]


def test_public_model_contracts_and_schemas_are_exact() -> None:
    expected = FIXTURE["public_models"]
    observed: list[dict[str, object]] = []
    for row in expected["contracts"]:
        model = resolve(row["module"], row["name"])
        assert isinstance(model, type)
        assert issubclass(model, BaseModel)
        observed.append(model_contract(model))
    observed.sort(key=lambda row: (str(row["module"]), str(row["name"])))
    assert observed == expected["contracts"]
    assert canonical_sha(observed) == expected["contracts_sha256"]


def test_public_enum_values_are_exact() -> None:
    observed: list[dict[str, object]] = []
    for row in FIXTURE["public_enums"]["enums"]:
        enum_type = resolve(row["module"], row["name"])
        observed.append(
            {
                "module": row["module"],
                "name": row["name"],
                "values": [member.value for member in enum_type],
            }
        )
    assert observed == FIXTURE["public_enums"]["enums"]
    assert canonical_sha(observed) == FIXTURE["public_enums"]["enums_sha256"]


def test_digest_domains_and_behavioral_vectors_are_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for row in FIXTURE["digest_domains"]["domains"]:
        module = importlib.import_module(row["module"])
        assert getattr(module, row["name"]).hex() == row["hex"]

    for vector in FIXTURE["digest_vectors"]["vectors"]:
        module = importlib.import_module(vector["module"])
        function = getattr(module, vector["function"])
        original_sha256 = module.sha256
        captures: list[CapturingHash] = []

        def factory(initial: bytes = b"") -> CapturingHash:
            capture = CapturingHash(original_sha256, initial)
            caller = sys._getframe(1)
            if (
                caller.f_code.co_name == vector["function"]
                and caller.f_globals.get("__name__") == vector["module"]
            ):
                captures.append(capture)
            return capture

        monkeypatch.setattr(module, "sha256", factory)
        type_hints = get_type_hints(function)
        arguments = {
            name: decode_argument(value, type_hints.get(name))
            for name, value in vector["arguments"].items()
        }
        result = function(**arguments)
        assert encode_value(result) == vector["result"]
        records = [record for capture in captures for record in capture.records]
        expected_record = {
            "message_hex": vector["message_hex"],
            "digest": vector["digest"],
        }
        assert records
        assert all(record == expected_record for record in records)
        monkeypatch.setattr(module, "sha256", original_sha256)


def test_canonical_json_bytes_are_exact() -> None:
    implementations = helper_implementations("_canonical_json")
    for vector in FIXTURE["canonical_json_vectors"]:
        for implementation in implementations:
            assert implementation(vector["value"]).hex() == vector["expected_hex"]


def test_aware_datetime_normalization_and_naive_error_are_exact() -> None:
    implementations = helper_implementations("_require_aware")
    for vector in FIXTURE["utc_vectors"]:
        value = datetime.fromisoformat(vector["input"])
        for implementation in implementations:
            assert implementation(value).isoformat() == vector["expected"]

    expected_error = FIXTURE["naive_datetime_error"]
    for implementation in implementations:
        with pytest.raises(ValueError) as captured:
            implementation(datetime(2026, 7, 19, 12, 0, 0))
        assert type(captured.value).__name__ == expected_error["type"]
        assert str(captured.value) == expected_error["message"]


@pytest.mark.parametrize("vector", FIXTURE["validation_error_vectors"])
def test_sorted_unique_validation_errors_are_exact(
    vector: dict[str, object],
) -> None:
    implementations = helper_implementations(str(vector["helper"]))
    values = (
        tuple(ProbeEnum(value) for value in vector["values"])
        if vector["kind"] == "enums"
        else tuple(vector["values"])
    )
    for implementation in implementations:
        with pytest.raises(ValueError) as captured:
            implementation(values, field_name=vector["field_name"])
        assert type(captured.value).__name__ == vector["expected_type"]
        assert str(captured.value) == vector["expected_message"]


def test_private_helpers_are_not_exported_by_the_public_facade() -> None:
    facade = importlib.import_module("systeme_local_gateway.providers")
    private_names = {
        "_canonical_json",
        "_require_aware",
        "_validate_sorted_unique_enum_tuple",
        "_validate_sorted_unique_string_tuple",
    }
    assert private_names.isdisjoint(facade.__all__)
