"""Deterministic JSON Schema compatibility classification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


UNCHANGED = "unchanged"
PATCH_COMPATIBLE = "patch-compatible"
ADDITIVE_MINOR = "additive-minor"
BREAKING_MAJOR = "breaking-major"


class SchemaCompatibilityError(ValueError):
    """Raised when a declared schema version under-declares its compatibility impact."""


@dataclass(frozen=True)
class SchemaCompatibilityResult:
    classification: str
    breaking_changes: tuple[str, ...]
    additive_changes: tuple[str, ...]
    patch_changes: tuple[str, ...] = ()

    @property
    def allowed_without_bump(self) -> bool:
        return self.classification == UNCHANGED


@dataclass
class _Diff:
    breaking: list[str]
    additive: list[str]
    patch: list[str]

    def mark_breaking(self, path: str, reason: str) -> None:
        self.breaking.append(f"{path}: {reason}")

    def mark_additive(self, path: str, reason: str) -> None:
        self.additive.append(f"{path}: {reason}")

    def mark_patch(self, path: str, reason: str) -> None:
        self.patch.append(f"{path}: {reason}")


def classify_json_schema_change(old_schema: Mapping[str, Any], new_schema: Mapping[str, Any]) -> SchemaCompatibilityResult:
    diff = _Diff(breaking=[], additive=[], patch=[])
    _walk_schema("$", old_schema, new_schema, diff)
    breaking = tuple(sorted(set(diff.breaking)))
    additive = tuple(sorted(set(diff.additive)))
    patch = tuple(sorted(set(diff.patch)))
    if breaking:
        classification = BREAKING_MAJOR
    elif additive:
        classification = ADDITIVE_MINOR
    elif patch:
        classification = PATCH_COMPATIBLE
    else:
        classification = UNCHANGED
    return SchemaCompatibilityResult(
        classification=classification,
        breaking_changes=breaking,
        additive_changes=additive,
        patch_changes=patch,
    )


def assert_schema_version_declares_change(
    *,
    old_version: str,
    new_version: str,
    classification: str,
) -> None:
    if not schema_version_declares_change(
        old_version=old_version,
        new_version=new_version,
        classification=classification,
    ):
        raise SchemaCompatibilityError(f"{new_version} under-declares {classification} from {old_version}")


def schema_version_declares_change(*, old_version: str, new_version: str, classification: str) -> bool:
    old = _semver(old_version)
    new = _semver(new_version)
    if new < old:
        return False
    if classification == UNCHANGED:
        return True
    if classification == PATCH_COMPATIBLE:
        return new > old
    if classification == ADDITIVE_MINOR:
        return new[0] > old[0] or (new[0] == old[0] and new[1] > old[1])
    if classification == BREAKING_MAJOR:
        return new[0] > old[0]
    raise SchemaCompatibilityError(f"unknown schema classification: {classification}")


def _walk_schema(path: str, old: Any, new: Any, diff: _Diff) -> None:
    if old == new:
        return
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        diff.mark_breaking(path, "schema node changed shape")
        return

    _compare_ref(path, old, new, diff)
    _compare_const(path, old, new, diff)
    _compare_type(path, old, new, diff)
    _compare_enum(path, old, new, diff)
    _compare_object(path, old, new, diff)
    _compare_arrays(path, old, new, diff)
    _compare_constraints(path, old, new, diff)
    _compare_combiners(path, old, new, diff)
    _compare_defs(path, old, new, diff)
    _compare_annotations(path, old, new, diff)


def _compare_ref(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    old_ref = old.get("$ref")
    new_ref = new.get("$ref")
    if old_ref == new_ref:
        return
    if old_ref is not None and new_ref is not None:
        diff.mark_breaking(path, f"$ref changed from {old_ref!r} to {new_ref!r}")
    elif old_ref is not None:
        diff.mark_breaking(path, "$ref removed")
    else:
        diff.mark_breaking(path, f"$ref added as {new_ref!r}")


def _compare_const(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    if "const" not in old and "const" not in new:
        return
    if old.get("const") == new.get("const"):
        return
    if "const" in old and "const" not in new:
        diff.mark_additive(path, "const removed")
    elif "const" not in old and "const" in new:
        diff.mark_breaking(path, "const added")
    else:
        diff.mark_breaking(path, "const changed")


def _compare_type(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    old_types = _type_set(old.get("type"))
    new_types = _type_set(new.get("type"))
    if old_types == new_types:
        return
    if old_types and new_types:
        removed = old_types - new_types
        added = new_types - old_types
        if removed:
            diff.mark_breaking(path, f"type narrowed; removed {sorted(removed)}")
        if added:
            diff.mark_additive(path, f"type broadened; added {sorted(added)}")
    elif old_types and not new_types:
        diff.mark_additive(path, "type restriction removed")
    elif new_types:
        diff.mark_breaking(path, f"type restriction added {sorted(new_types)}")


def _compare_enum(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    old_enum = old.get("enum")
    new_enum = new.get("enum")
    if old_enum == new_enum:
        return
    if old_enum is None and new_enum is None:
        return
    if old_enum is None:
        diff.mark_breaking(path, "enum restriction added")
        return
    if new_enum is None:
        diff.mark_additive(path, "enum restriction removed")
        return
    old_values = {_json_key(value) for value in old_enum}
    new_values = {_json_key(value) for value in new_enum}
    removed = old_values - new_values
    added = new_values - old_values
    if removed:
        diff.mark_breaking(path, f"enum values removed {sorted(removed)}")
    if added:
        diff.mark_additive(path, f"enum values added {sorted(added)}")


def _compare_object(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    old_props = _mapping(old.get("properties"))
    new_props = _mapping(new.get("properties"))
    old_required = set(_string_list(old.get("required")))
    new_required = set(_string_list(new.get("required")))

    for name in sorted(old_props.keys() - new_props.keys()):
        diff.mark_breaking(f"{path}.properties.{name}", "property removed")
    for name in sorted(new_props.keys() - old_props.keys()):
        prop_path = f"{path}.properties.{name}"
        if name in new_required and not _has_default(new_props[name]):
            diff.mark_breaking(prop_path, "required property added without default")
        else:
            diff.mark_additive(prop_path, "property added")
    for name in sorted(old_props.keys() & new_props.keys()):
        _walk_schema(f"{path}.properties.{name}", old_props[name], new_props[name], diff)

    for name in sorted(old_required - new_required):
        diff.mark_breaking(f"{path}.required.{name}", "required field no longer guaranteed")
    for name in sorted(new_required - old_required):
        if name in old_props and not _has_default(new_props.get(name, {})):
            diff.mark_breaking(f"{path}.required.{name}", "existing property made required without default")
        elif name in old_props:
            diff.mark_additive(f"{path}.required.{name}", "existing property made required with default")

    _compare_additional_properties(path, old, new, diff)


def _compare_additional_properties(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    sentinel = object()
    old_value = old.get("additionalProperties", sentinel)
    new_value = new.get("additionalProperties", sentinel)
    if old_value is sentinel and new_value is sentinel:
        return
    old_effective = True if old_value is sentinel else old_value
    new_effective = True if new_value is sentinel else new_value
    if old_effective == new_effective:
        if isinstance(old_effective, Mapping) and isinstance(new_effective, Mapping):
            _walk_schema(f"{path}.additionalProperties", old_effective, new_effective, diff)
        return
    if old_effective is False and new_effective is not False:
        diff.mark_additive(f"{path}.additionalProperties", "additional properties loosened")
    elif old_effective is not False and new_effective is False:
        diff.mark_breaking(f"{path}.additionalProperties", "additional properties tightened")
    elif isinstance(old_effective, Mapping) and isinstance(new_effective, Mapping):
        _walk_schema(f"{path}.additionalProperties", old_effective, new_effective, diff)
    else:
        diff.mark_breaking(f"{path}.additionalProperties", "additional properties constraint changed")


def _compare_arrays(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    for key in ("items", "prefixItems", "contains"):
        old_value = old.get(key)
        new_value = new.get(key)
        if old_value == new_value:
            continue
        item_path = f"{path}.{key}"
        if isinstance(old_value, Mapping) and isinstance(new_value, Mapping):
            _walk_schema(item_path, old_value, new_value, diff)
        elif isinstance(old_value, list) and isinstance(new_value, list):
            _compare_schema_list(item_path, old_value, new_value, diff)
        elif old_value is None:
            diff.mark_breaking(item_path, "array constraint added")
        elif new_value is None:
            diff.mark_additive(item_path, "array constraint removed")
        else:
            diff.mark_breaking(item_path, "array constraint changed")


def _compare_constraints(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    for key in ("minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties"):
        _compare_lower_bound(path, key, old, new, diff)
    for key in ("maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties"):
        _compare_upper_bound(path, key, old, new, diff)
    for key in ("pattern", "format", "multipleOf", "uniqueItems"):
        _compare_exact_constraint(path, key, old, new, diff)


def _compare_lower_bound(path: str, key: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    old_value = old.get(key)
    new_value = new.get(key)
    if old_value == new_value:
        return
    if old_value is None:
        diff.mark_breaking(f"{path}.{key}", "lower bound added")
    elif new_value is None:
        diff.mark_additive(f"{path}.{key}", "lower bound removed")
    elif new_value > old_value:
        diff.mark_breaking(f"{path}.{key}", f"lower bound raised from {old_value} to {new_value}")
    else:
        diff.mark_additive(f"{path}.{key}", f"lower bound lowered from {old_value} to {new_value}")


def _compare_upper_bound(path: str, key: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    old_value = old.get(key)
    new_value = new.get(key)
    if old_value == new_value:
        return
    if old_value is None:
        diff.mark_breaking(f"{path}.{key}", "upper bound added")
    elif new_value is None:
        diff.mark_additive(f"{path}.{key}", "upper bound removed")
    elif new_value < old_value:
        diff.mark_breaking(f"{path}.{key}", f"upper bound lowered from {old_value} to {new_value}")
    else:
        diff.mark_additive(f"{path}.{key}", f"upper bound raised from {old_value} to {new_value}")


def _compare_exact_constraint(path: str, key: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    old_value = old.get(key)
    new_value = new.get(key)
    if old_value == new_value:
        return
    if old_value is None:
        diff.mark_breaking(f"{path}.{key}", "constraint added")
    elif new_value is None:
        diff.mark_additive(f"{path}.{key}", "constraint removed")
    else:
        diff.mark_breaking(f"{path}.{key}", "constraint changed")


def _compare_combiners(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    for key in ("allOf", "anyOf", "oneOf"):
        old_items = old.get(key)
        new_items = new.get(key)
        if old_items == new_items:
            continue
        if not isinstance(old_items, list) or not isinstance(new_items, list):
            if old_items is None:
                diff.mark_breaking(f"{path}.{key}", "combiner added")
            elif new_items is None:
                diff.mark_additive(f"{path}.{key}", "combiner removed")
            else:
                diff.mark_breaking(f"{path}.{key}", "combiner changed shape")
            continue
        _compare_schema_list(f"{path}.{key}", old_items, new_items, diff)


def _compare_schema_list(path: str, old_items: list[Any], new_items: list[Any], diff: _Diff) -> None:
    old_len = len(old_items)
    new_len = len(new_items)
    for index in range(min(old_len, new_len)):
        _walk_schema(f"{path}[{index}]", old_items[index], new_items[index], diff)
    if new_len < old_len:
        diff.mark_breaking(path, f"schema alternatives removed ({old_len}->{new_len})")
    elif new_len > old_len:
        diff.mark_additive(path, f"schema alternatives added ({old_len}->{new_len})")


def _compare_defs(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    for key in ("$defs", "definitions"):
        old_defs = _mapping(old.get(key))
        new_defs = _mapping(new.get(key))
        for name in sorted(old_defs.keys() - new_defs.keys()):
            diff.mark_breaking(f"{path}.{key}.{name}", "definition removed")
        for name in sorted(new_defs.keys() - old_defs.keys()):
            diff.mark_additive(f"{path}.{key}.{name}", "definition added")
        for name in sorted(old_defs.keys() & new_defs.keys()):
            _walk_schema(f"{path}.{key}.{name}", old_defs[name], new_defs[name], diff)


def _compare_annotations(path: str, old: Mapping[str, Any], new: Mapping[str, Any], diff: _Diff) -> None:
    annotation_keys = {
        "$comment",
        "$id",
        "$schema",
        "description",
        "examples",
        "title",
        "x-argus-contract",
    }
    ignored_keys = annotation_keys | {
        "$defs",
        "$ref",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "definitions",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "oneOf",
        "pattern",
        "prefixItems",
        "properties",
        "required",
        "type",
        "uniqueItems",
    }
    changed_annotations = sorted(key for key in annotation_keys if old.get(key) != new.get(key))
    if changed_annotations:
        diff.mark_patch(path, f"annotations changed {changed_annotations}")
    old_unknown = set(old) - ignored_keys
    new_unknown = set(new) - ignored_keys
    for key in sorted(old_unknown | new_unknown):
        if old.get(key) != new.get(key):
            diff.mark_breaking(f"{path}.{key}", "unsupported schema keyword changed")


def _type_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return {"<invalid-type-keyword>"}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    return ()


def _has_default(value: Any) -> bool:
    return isinstance(value, Mapping) and "default" in value


def _json_key(value: Any) -> str:
    return repr(value)


def _semver(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3:
        raise SchemaCompatibilityError(f"invalid semver: {version}")
    try:
        return tuple(int(part) for part in parts)  # type: ignore[return-value]
    except ValueError as exc:
        raise SchemaCompatibilityError(f"invalid semver: {version}") from exc
