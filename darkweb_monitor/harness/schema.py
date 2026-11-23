"""Minimal JSON-schema validation for tool arguments (subset used by tools)."""
from __future__ import annotations

import json
import re

from .errors import ToolArgsError

_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
          "array": list, "object": dict, "null": type(None)}


def _check(value, schema: dict, path: str) -> None:
    t = schema.get("type")
    if t:
        types = t if isinstance(t, list) else [t]
        ok = False
        for tt in types:
            py = _TYPES.get(tt)
            if py is None:
                continue
            if tt in ("integer", "number") and isinstance(value, bool):
                continue
            if isinstance(value, py):
                ok = True
                break
        if not ok:
            raise ToolArgsError(f"{path or 'arguments'}: expected {t}, got {type(value).__name__}")
    if "enum" in schema and value not in schema["enum"]:
        raise ToolArgsError(f"{path}: must be one of {schema['enum']}")
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ToolArgsError(f"{path}: longer than {schema['maxLength']} characters")
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ToolArgsError(f"{path}: shorter than {schema['minLength']} characters")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ToolArgsError(f"{path}: must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ToolArgsError(f"{path}: must be <= {schema['maximum']}")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ToolArgsError(f"{path}: more than {schema['maxItems']} items")
        if "items" in schema:
            for i, v in enumerate(value):
                _check(v, schema["items"], f"{path}[{i}]")
    if isinstance(value, dict) and (schema.get("type") == "object" or "properties" in schema):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                raise ToolArgsError(f"{path + '.' if path else ''}{req}: required")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                raise ToolArgsError(f"{path or 'arguments'}: unexpected field(s) {sorted(extra)}")
        for k, v in value.items():
            if k in props:
                _check(v, props[k], f"{path + '.' if path else ''}{k}")


def validate(args, schema: dict) -> dict:
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ToolArgsError("arguments must be a JSON object")
    _check(args, {"type": "object", **schema}, "")
    return args


# --------------------------------------------------------------- input repair
def _coerce(value, schema: dict):
    """Repair common small-model mistakes when the schema makes the intent
    unambiguous (adapted from opencode's tool-input repair)."""
    t = schema.get("type")
    if isinstance(value, str):
        v = value.strip()
        if t == "integer" and re.fullmatch(r"-?\d+", v):
            return int(v)
        if t == "number" and re.fullmatch(r"-?\d+(?:\.\d+)?", v):
            return float(v)
        if t == "boolean" and v.lower() in ("true", "false", "yes", "no", "1", "0"):
            return v.lower() in ("true", "yes", "1")
        if t in ("array", "object") and v[:1] in "[{":
            try:
                return _coerce(json.loads(v), schema)
            except ValueError:
                return value
        if t == "array":
            return [_coerce(x.strip(), schema.get("items", {})) for x in v.split(",") if x.strip()]
        if "enum" in schema and value not in schema["enum"]:
            for e in schema["enum"]:
                if isinstance(e, str) and e.lower() == v.lower().replace(" ", "_"):
                    return e
    if t == "array" and not isinstance(value, list) and value is not None:
        return [_coerce(value, schema.get("items", {}))]
    if isinstance(value, list) and t == "array":
        return [_coerce(x, schema.get("items", {})) for x in value]
    if isinstance(value, dict) and (t == "object" or "properties" in schema):
        return repair(value, schema)
    return value


def repair(args, schema: dict) -> dict:
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return args
    if not isinstance(args, dict):
        return args
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    out = {}
    for k, v in args.items():
        key = k if k in props else next((p for p in props if p.lower() == str(k).lower()), k)
        if v is None and key not in required:
            continue  # optional null placeholder
        if key not in props and schema.get("additionalProperties") is False:
            continue  # closed object: drop unknown fields instead of failing
        out[key] = _coerce(v, props.get(key, {}))
    return out
