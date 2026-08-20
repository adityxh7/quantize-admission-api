import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful freeze store.
FREEZES = {}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utf8_sort_key(value: str):
    return value.encode("utf-8")


def sorted_codes(codes):
    return sorted(set(codes), key=utf8_sort_key)


def nonempty_string(value):
    return isinstance(value, str) and len(value) > 0


def unique_strings(value):
    if not isinstance(value, list):
        return False
    if not all(nonempty_string(x) for x in value):
        return False
    return len(value) == len(set(value))


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 9007199254740991
    )


def finite_nonnegative(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def finite_floor(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def build_inventory(files):
    """
    Build:
      inventory
      totalBytes
      packageDigest

    Files are treated as UTF-8 text data.
    """

    if not isinstance(files, dict) or not files:
        return None

    inventory = []
    names = set()

    for filename, content in files.items():

        if not isinstance(filename, str) or not filename:
            return None

        if filename in names:
            return None

        names.add(filename)

        if not isinstance(content, str):
            return None

        try:
            encoded = content.encode("utf-8")
        except UnicodeEncodeError:
            return None

        inventory.append(
            {
                "name": filename,
                "bytes": len(encoded),
                "sha256": sha256_bytes(encoded),
            }
        )

    inventory.sort(key=lambda x: utf8_sort_key(x["name"]))

    total = sum(item["bytes"] for item in inventory)

    digest = sha256_bytes(compact_json(inventory))

    return inventory, total, digest


def valid_freeze_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not nonempty_string(freeze_id):
        return False

    if len(freeze_id) > 128:
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False

    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    if not unique_strings(body.get("allowedUnsupportedReasons")):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

        files = candidate.get("files")

        if not isinstance(files, dict) or len(files) == 0:
            return False

        for filename, content in files.items():
            if not isinstance(filename, str) or not filename:
                return False
            if not isinstance(content, str):
                return False

    if len(names) != len(set(names)):
        return False

    return True


def perform_freeze(body):

    freeze_id = body["freezeId"]

    # Existing ID.
    if freeze_id in FREEZES:

        existing = FREEZES[freeze_id]

        # Exact replay.
        if existing["request"] == body:
            return existing["response"], 200

        # Same ID, different request.
        return {"error": "FREEZE_ID_CONFLICT"}, 409

    calibration = body["calibrationDigest"]
    tokenizer = body["tokenizerDigest"]

    allowed_reasons = set(body["allowedUnsupportedReasons"])

    candidates = []

    for candidate in body["candidates"]:

        name = candidate["name"]

        inventory_result = build_inventory(candidate["files"])

        # Invalid files.
        if inventory_result is None:

            candidates.append(
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

        reasons = []

        unsupported_reason = candidate.get("unsupportedReason")

        # Unsupported candidate.
        if unsupported_reason is not None:

            if (
                not nonempty_string(unsupported_reason)
                or unsupported_reason not in allowed_reasons
            ):
                reasons.append("UNALLOWED_UNSUPPORTED_REASON")
            else:
                candidates.append(
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
            reasons.append("NOT_LOADABLE")

        if candidate.get("calibrationDigest") != calibration:
            reasons.append("CALIBRATION_MISMATCH")

        if candidate.get("tokenizerDigest") != tokenizer:
            reasons.append("TOKENIZER_MISMATCH")

        if reasons:

            candidates.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": sorted_codes(reasons),
                }
            )

        else:

            candidates.append(
                {
                    "name": name,
                    "status": "frozen",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": [],
                }
            )

    candidates.sort(key=lambda x: utf8_sort_key(x["name"]))

    response = {
        "freezeId": freeze_id,
        "candidates": candidates,
    }

    FREEZES[freeze_id] = {
        "request": body,
        "response": response,
    }

    return response, 200


def recompute_inventory_from_manifest(manifest):

    inventory = manifest.get("inventory")

    if not isinstance(inventory, list):
        return None

    names = set()
    rebuilt = []

    for item in inventory:

        if not isinstance(item, dict):
            return None

        name = item.get("name")
        bytes_value = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return None

        if name in names:
            return None

        names.add(name)

        if not safe_integer(bytes_value):
            return None

        if not isinstance(digest, str) or len(digest) != 64:
            return None

        try:
            int(digest, 16)
        except ValueError:
            return None

        rebuilt.append(
            {
                "name": name,
                "bytes": bytes_value,
                "sha256": digest,
            }
        )

    rebuilt.sort(key=lambda x: utf8_sort_key(x["name"]))

    if rebuilt != inventory:
        return None

    total = sum(x["bytes"] for x in inventory)

    digest = sha256_bytes(compact_json(inventory))

    return inventory, total, digest


def manifest_is_valid(record):

    if not isinstance(record, dict):
        return False

    rebuilt = recompute_inventory_from_manifest(record)

    if rebuilt is None:
        return False

    inventory, total, digest = rebuilt

    if record.get("totalBytes") != total:
        return False

    if record.get("packageDigest") != digest:
        return False

    return True


def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    if not safe_integer(policy.get("maxBytes")):
        return False

    if not finite_floor(policy.get("aggregateFloor")):
        return False

    if not finite_nonnegative(policy.get("maxLatencyMs")):
        return False

    required = policy.get("requiredSlices")

    if not isinstance(required, dict):
        return False

    for name, floor in required.items():

        if not nonempty_string(name):
            return False

        if not finite_floor(floor):
            return False

    order = policy.get("candidateOrder")

    if not unique_strings(order):
        return False

    return True


def prediction_is_binary(value):
    return value == 0 or value == 1


def calculate_candidate_metrics(name, rows):

    if not isinstance(rows, list) or len(rows) == 0:
        return None, None, False

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            return None, None, False

        if "label" not in row:
            return None, None, False

        label = row["label"]

        if not prediction_is_binary(label):
            return None, None, False

        predictions = row.get("predictions")

        if not isinstance(predictions, dict):
            return None, None, False

        if name not in predictions:
            return None, None, False

        prediction = predictions[name]

        if not prediction_is_binary(prediction):
            return None, None, False

        if prediction == label:
            correct += 1

        slice_name = row.get("slice")

        if not isinstance(slice_name, str) or not slice_name:
            return None, None, False

        if slice_name not in slice_total:
            slice_total[slice_name] = 0
            slice_correct[slice_name] = 0

        slice_total[slice_name] += 1

        if prediction == label:
            slice_correct[slice_name] += 1

    aggregate = round(correct / len(rows), 12)

    slices = {}

    for slice_name in sorted(slice_total, key=utf8_sort_key):

        slices[slice_name] = round(
            slice_correct[slice_name] / slice_total[slice_name],
            12,
        )

    return aggregate, slices, True


def perform_select(body):

    freeze_id = body.get("freezeId")

    stored = FREEZES.get(freeze_id)

    # Unknown freeze.
    if stored is None:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    supplied_candidates = body["candidates"]
    rows = body["rows"]
    policy = body["policy"]

    stored_candidates = stored["response"]["candidates"]

    stored_names = [x["name"] for x in stored_candidates]

    supplied_names = []

    for candidate in supplied_candidates:

        if isinstance(candidate, dict):
            supplied_names.append(candidate.get("name"))
        else:
            supplied_names.append(None)

    lineage_invalid = (
        supplied_candidates != stored_candidates
        or len(supplied_names) != len(stored_names)
        or len(set(supplied_names)) != len(supplied_names)
        or set(supplied_names) != set(stored_names)
    )

    policy_invalid = not validate_policy(policy)

    order = policy.get("candidateOrder", [])

    if (
        not policy_invalid
        and (
            len(order) != len(stored_names)
            or len(set(order)) != len(order)
            or set(order) != set(stored_names)
        )
    ):
        policy_invalid = True

    latencies = body.get("latencies")

    if not isinstance(latencies, dict):
        policy_invalid = True

    frozen_by_name = {
        x["name"]: x
        for x in stored_candidates
    }

    results = []

    for candidate in supplied_candidates:

        name = candidate.get("name") if isinstance(candidate, dict) else None

        reasons = []

        if lineage_invalid:
            reasons.append("INVALID_LINEAGE")

        if policy_invalid:
            reasons.append("INVALID_POLICY")

        record = frozen_by_name.get(name)

        # Verify the candidate manifest against the frozen response.
        manifest_valid = False

        if record is not None and isinstance(candidate, dict):

            manifest_valid = (
                candidate == record
                and manifest_is_valid(candidate)
            )

        if not manifest_valid:
            reasons.append("INVALID_MANIFEST")

        aggregate, slices, predictions_valid = calculate_candidate_metrics(
            name,
            rows,
        )

        if not predictions_valid:
            reasons.append("INVALID_PREDICTIONS")

        total_bytes = None

        if manifest_valid:
            total_bytes = record["totalBytes"]

        latency_ms = None

        if isinstance(latencies, dict) and name in latencies:

            latency_value = latencies[name]

            if finite_nonnegative(latency_value):
                latency_ms = latency_value

        if (
            aggregate is not None
            and not policy_invalid
        ):

            if aggregate < policy["aggregateFloor"]:
                reasons.append("AGGREGATE_FLOOR")

            for slice_name, floor in policy["requiredSlices"].items():

                if slice_name not in slices:
                    reasons.append(
                        f"MISSING_SLICE:{slice_name}"
                    )

                elif slices[slice_name] < floor:
                    reasons.append(
                        f"SLICE_FLOOR:{slice_name}"
                    )

            if total_bytes is not None:

                if total_bytes > policy["maxBytes"]:
                    reasons.append("SIZE_LIMIT")

            if latency_ms is not None:

                if latency_ms > policy["maxLatencyMs"]:
                    reasons.append("LATENCY_LIMIT")

        # Only genuinely frozen candidates can be admitted.
        if record is None:
            reasons.append("INVALID_LINEAGE")
        elif record["status"] != "frozen":
            reasons.append("INVALID_LINEAGE")

        reasons = sorted_codes(reasons)

        admitted = len(reasons) == 0

        results.append(
            {
                "name": name,
                "aggregate": aggregate,
                "slices": slices if predictions_valid else {},
                "totalBytes": total_bytes,
                "latencyMs": latency_ms,
                "admitted": admitted,
                "reasonCodes": reasons,
            }
        )

    order_index = {
        name: index
        for index, name in enumerate(order)
    }

    results.sort(
        key=lambda x: (
            order_index.get(x["name"], len(order)),
            utf8_sort_key(x["name"] or ""),
        )
    )

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    selected = None
    package_manifest = None

    if admitted:

        winner = min(
            admitted,
            key=lambda x: (
                x["totalBytes"],
                float(x["latencyMs"]),
                order_index.get(x["name"], len(order)),
                utf8_sort_key(x["name"]),
            ),
        )

        selected = winner["name"]
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

    print("QUANTIZE_REQUEST:", json.dumps(body, ensure_ascii=False, separators=(",", ":")), flush=True)

    if phase == "freeze":

        if not valid_freeze_request(body):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        response, status = perform_freeze(body)

        return JSONResponse(
            response,
            status_code=status,
        )

    if phase == "select":

        # Exact required top-level structure.
        if (
            not isinstance(body.get("candidates"), list)
            or not isinstance(body.get("rows"), list)
            or not isinstance(body.get("policy"), dict)
        ):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        response, status = perform_select(body)

        return JSONResponse(
            response,
            status_code=status,
        )

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