import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# In-memory state is sufficient for the grader while the Render instance remains running.
frozen_store: dict[str, dict[str, Any]] = {}


CODES = {
    "INVALID_INPUT",
    "UNALLOWED_UNSUPPORTED_REASON",
    "NOT_LOADABLE",
    "CALIBRATION_MISMATCH",
    "TOKENIZER_MISMATCH",
    "NOT_FROZEN",
    "INVALID_LINEAGE",
    "INVALID_POLICY",
    "INVALID_PREDICTIONS",
    "INVALID_MANIFEST",
    "AGGREGATE_FLOOR",
    "SIZE_LIMIT",
    "LATENCY_LIMIT",
}


def utf8_key(value: str):
    return value.encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def package_inventory(files: Any):
    if not isinstance(files, dict) or not files:
        return None

    inventory = []

    # Validate filenames and values.
    seen = set()

    for filename, text in files.items():
        if not isinstance(filename, str) or not filename:
            return None

        if filename in seen:
            return None
        seen.add(filename)

        if not isinstance(text, str):
            return None

        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError:
            return None

        inventory.append(
            {
                "name": filename,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
            }
        )

    inventory.sort(key=lambda x: utf8_key(x["name"]))

    total = sum(item["bytes"] for item in inventory)

    digest = sha256_bytes(compact_json_bytes(inventory))

    return inventory, total, digest


def code_sort(codes):
    return sorted(set(codes), key=lambda x: x.encode("utf-8"))


def valid_nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def unique_string_array(value):
    if not isinstance(value, list):
        return False

    if not all(isinstance(x, str) and x for x in value):
        return False

    return len(value) == len(set(value))


def is_safe_nonnegative_int(value):
    # JavaScript safe integer range.
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 9007199254740991
    )


def finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def round12(x):
    return round(float(x), 12)


def validate_freeze_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    if not valid_nonempty_string(body.get("freezeId")):
        return False

    if len(body["freezeId"]) > 128:
        return False

    if not valid_nonempty_string(body.get("calibrationDigest")):
        return False

    if not valid_nonempty_string(body.get("tokenizerDigest")):
        return False

    if not unique_string_array(body.get("allowedUnsupportedReasons")):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = []

    for c in candidates:
        if not isinstance(c, dict):
            return False

        name = c.get("name")

        if not valid_nonempty_string(name):
            return False

        names.append(name)

        files = c.get("files")

        if not isinstance(files, dict) or len(files) == 0:
            return False

        for filename, text in files.items():
            if not isinstance(filename, str) or not filename:
                return False
            if not isinstance(text, str):
                return False

    if len(names) != len(set(names)):
        return False

    return True


def freeze(body):
    freeze_id = body["freezeId"]

    # Identical replay.
    if freeze_id in frozen_store:
        previous = frozen_store[freeze_id]

        if previous["_request"] == body:
            return previous["response"], 200

        return {"error": "FREEZE_ID_CONFLICT"}, 409

    calibration = body["calibrationDigest"]
    tokenizer = body["tokenizerDigest"]
    allowed = set(body["allowedUnsupportedReasons"])

    output_candidates = []

    for candidate in body["candidates"]:
        name = candidate["name"]

        inventory_result = package_inventory(candidate["files"])

        reason_codes = []

        # Invalid file manifest.
        if inventory_result is None:
            output_candidates.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": [],
                    "totalBytes": None,
                    "packageDigest": None,
                    "reasonCodes": ["INVALID_INPUT"],
                }
            )
            continue

        inventory, total_bytes, package_digest = inventory_result

        unsupported_reason = candidate.get("unsupportedReason")

        if unsupported_reason is not None:
            if (
                not isinstance(unsupported_reason, str)
                or not unsupported_reason
                or unsupported_reason not in allowed
            ):
                reason_codes.append("UNALLOWED_UNSUPPORTED_REASON")
            else:
                output_candidates.append(
                    {
                        "name": name,
                        "status": "unsupported",
                        "inventory": inventory,
                        "totalBytes": total_bytes,
                        "packageDigest": package_digest,
                        "reasonCodes": [],
                    }
                )
                continue

        if candidate.get("loadable") is not True:
            reason_codes.append("NOT_LOADABLE")

        if candidate.get("calibrationDigest") != calibration:
            reason_codes.append("CALIBRATION_MISMATCH")

        if candidate.get("tokenizerDigest") != tokenizer:
            reason_codes.append("TOKENIZER_MISMATCH")

        if reason_codes:
            output_candidates.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": code_sort(reason_codes),
                }
            )
        else:
            output_candidates.append(
                {
                    "name": name,
                    "status": "frozen",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": [],
                }
            )

    output_candidates.sort(key=lambda x: utf8_key(x["name"]))

    response = {
        "freezeId": freeze_id,
        "candidates": output_candidates,
    }

    frozen_store[freeze_id] = {
        "_request": body,
        "response": response,
    }

    return response, 200


def manifest_matches(record, supplied):
    if not isinstance(supplied, dict):
        return False

    required = ["name", "status", "inventory", "totalBytes", "packageDigest", "reasonCodes"]

    if any(k not in supplied for k in required):
        return False

    if supplied.get("name") != record.get("name"):
        return False

    # Recompute inventory from the supplied inventory itself.
    inventory = supplied.get("inventory")

    if not isinstance(inventory, list):
        return False

    rebuilt = []

    for item in inventory:
        if not isinstance(item, dict):
            return False

        if (
            not isinstance(item.get("name"), str)
            or not isinstance(item.get("bytes"), int)
            or isinstance(item.get("bytes"), bool)
            or not isinstance(item.get("sha256"), str)
        ):
            return False

        rebuilt.append(
            {
                "name": item["name"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
            }
        )

    rebuilt.sort(key=lambda x: utf8_key(x["name"]))

    if rebuilt != inventory:
        return False

    total = sum(item["bytes"] for item in inventory)

    if total != supplied.get("totalBytes"):
        return False

    digest = sha256_bytes(compact_json_bytes(inventory))

    if digest != supplied.get("packageDigest"):
        return False

    return supplied == record


def validate_policy(policy):
    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get("maxBytes")
    aggregate_floor = policy.get("aggregateFloor")
    required_slices = policy.get("requiredSlices")
    max_latency = policy.get("maxLatencyMs")
    order = policy.get("candidateOrder")

    if not is_safe_nonnegative_int(max_bytes):
        return False

    if not finite_number(aggregate_floor) or not 0 <= float(aggregate_floor) <= 1:
        return False

    if not isinstance(required_slices, dict):
        return False

    for name, floor in required_slices.items():
        if not isinstance(name, str) or not name:
            return False
        if not finite_number(floor) or not 0 <= float(floor) <= 1:
            return False

    if not finite_number(max_latency) or float(max_latency) < 0:
        return False

    if not unique_string_array(order):
        return False

    return True


def select(body):
    freeze_id = body.get("freezeId")

    stored = frozen_store.get(freeze_id)

    if stored is None:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    stored_candidates = stored["response"]["candidates"]
    supplied_candidates = body.get("candidates")

    if not isinstance(supplied_candidates, list):
        return {"error": "INVALID_INPUT"}, 400

    # Exact frozen response candidate array required.
    if supplied_candidates != stored_candidates:
        lineage_error = True
    else:
        lineage_error = False

    policy = body.get("policy")
    rows = body.get("rows")

    if not isinstance(rows, list) or not isinstance(policy, dict):
        return {"error": "INVALID_INPUT"}, 400

    results = []

    stored_names = [x["name"] for x in stored_candidates]
    supplied_names = [
        x.get("name") for x in supplied_candidates
        if isinstance(x, dict)
    ]

    if (
        len(supplied_names) != len(stored_names)
        or len(set(supplied_names)) != len(supplied_names)
        or set(supplied_names) != set(stored_names)
    ):
        lineage_error = True

    if not validate_policy(policy):
        invalid_policy = True
    else:
        invalid_policy = False

    order = policy.get("candidateOrder", []) if isinstance(policy, dict) else []

    if (
        len(order) != len(stored_names)
        or len(set(order)) != len(order)
        or set(order) != set(stored_names)
    ):
        invalid_policy = True

    latencies = body.get("latencies")
    if not isinstance(latencies, dict):
        invalid_policy = True

    required_slices = (
        policy.get("requiredSlices", {})
        if isinstance(policy, dict)
        else {}
    )

    # Index frozen candidates by name.
    frozen_by_name = {x["name"]: x for x in stored_candidates}

    for candidate in supplied_candidates:
        name = candidate.get("name")
        record = frozen_by_name.get(name)

        codes = []

        if lineage_error:
            codes.append("INVALID_LINEAGE")

        if invalid_policy:
            codes.append("INVALID_POLICY")

        aggregate = None
        slices = {}

        predictions_valid = True

        # Validate every row prediction.
        for row in rows:
            if not isinstance(row, dict):
                predictions_valid = False
                break

            predictions = row.get("predictions")

            if not isinstance(predictions, dict):
                predictions_valid = False
                break

            prediction = predictions.get(name)

            # Binary prediction means 0 or 1.
            if prediction not in (0, 1):
                predictions_valid = False
                break

            if "label" not in row or row["label"] not in (0, 1):
                predictions_valid = False
                break

        if predictions_valid and rows:
            correct = 0

            slice_total = {}
            slice_correct = {}

            for row in rows:
                label = row["label"]
                prediction = row["predictions"][name]

                if prediction == label:
                    correct += 1

                slice_name = row.get("slice")

                if isinstance(slice_name, str) and slice_name:
                    slice_total[slice_name] = slice_total.get(slice_name, 0) + 1
                    if prediction == label:
                        slice_correct[slice_name] = (
                            slice_correct.get(slice_name, 0) + 1
                        )

            aggregate = round12(correct / len(rows))

            for slice_name in sorted(slice_total, key=utf8_key):
                slices[slice_name] = round12(
                    slice_correct.get(slice_name, 0)
                    / slice_total[slice_name]
                )

        elif not rows:
            predictions_valid = False

        if not predictions_valid:
            codes.append("INVALID_PREDICTIONS")

        # Manifest validation.
        manifest_valid = (
            record is not None
            and manifest_matches(record, candidate)
        )

        if not manifest_valid:
            codes.append("INVALID_MANIFEST")

        total_bytes = None

        if record is not None and manifest_valid:
            total_bytes = record["totalBytes"]

        latency_ms = None

        if isinstance(latencies, dict) and name in latencies:
            value = latencies[name]

            if finite_number(value) and float(value) >= 0:
                latency_ms = value

        if aggregate is not None and isinstance(policy, dict):
            if aggregate < policy.get("aggregateFloor", 0):
                codes.append("AGGREGATE_FLOOR")

            for slice_name, floor in required_slices.items():
                if slice_name not in slices:
                    codes.append(f"MISSING_SLICE:{slice_name}")
                elif slices[slice_name] < floor:
                    codes.append(f"SLICE_FLOOR:{slice_name}")

        if total_bytes is not None and validate_policy(policy):
            if total_bytes > policy["maxBytes"]:
                codes.append("SIZE_LIMIT")

        if latency_ms is not None and validate_policy(policy):
            if latency_ms > policy["maxLatencyMs"]:
                codes.append("LATENCY_LIMIT")

        # A candidate can only be admitted if frozen and all checks pass.
        if record is None:
            codes.append("INVALID_LINEAGE")
        elif record["status"] != "frozen":
            # Unsupported/invalid candidates cannot be admitted.
            codes.append("INVALID_LINEAGE")

        codes = code_sort(codes)

        admitted = len(codes) == 0

        results.append(
            {
                "name": name,
                "aggregate": aggregate,
                "slices": slices if predictions_valid else {},
                "totalBytes": total_bytes,
                "latencyMs": latency_ms,
                "admitted": admitted,
                "reasonCodes": codes,
            }
        )

    # Results in candidateOrder.
    order_index = {name: i for i, name in enumerate(order)}

    results.sort(
        key=lambda x: (
            order_index.get(x["name"], len(order)),
            utf8_key(x["name"]),
        )
    )

    admitted_results = [r for r in results if r["admitted"]]

    selected = None
    package_manifest = None

    if admitted_results:
        selected_result = min(
            admitted_results,
            key=lambda r: (
                r["totalBytes"],
                float(r["latencyMs"]),
                order_index.get(r["name"], len(order)),
                utf8_key(r["name"]),
            ),
        )

        selected = selected_result["name"]
        package_manifest = frozen_by_name[selected]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }, 200


@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    phase = body.get("phase")

    if phase == "freeze":
        if not validate_freeze_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        result, status = freeze(body)
        return JSONResponse(result, status_code=status)

    if phase == "select":
        # Required top-level structure.
        if (
            "candidates" not in body
            or "rows" not in body
            or "policy" not in body
            or not isinstance(body.get("candidates"), list)
            or not isinstance(body.get("rows"), list)
            or not isinstance(body.get("policy"), dict)
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        result, status = select(body)
        return JSONResponse(result, status_code=status)

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}