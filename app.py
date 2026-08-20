import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful storage for frozen requests.
FREEZES = {}


# ---------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------

def utf8_key(value: str):
    return value.encode("utf-8")


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sorted_codes(codes):
    return sorted(set(codes), key=utf8_key)


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


def binary_value(value):
    return value == 0 or value == 1


# ---------------------------------------------------------
# Inventory / package digest
# ---------------------------------------------------------

def build_inventory(files):
    """
    Files are UTF-8 strings.

    Returns:
        inventory, totalBytes, packageDigest

    Empty files are handled as an invalid candidate manifest,
    not as an invalid whole request.
    """

    if not isinstance(files, dict):
        return None

    if len(files) == 0:
        return [], None, None

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

    inventory.sort(
        key=lambda item: utf8_key(item["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_bytes(
        compact_json(inventory)
    )

    return inventory, total_bytes, package_digest


# ---------------------------------------------------------
# Freeze validation
# ---------------------------------------------------------

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

    if not nonempty_string(
        body.get("calibrationDigest")
    ):
        return False

    if not nonempty_string(
        body.get("tokenizerDigest")
    ):
        return False

    if not unique_strings(
        body.get("allowedUnsupportedReasons")
    ):
        return False

    candidates = body.get("candidates")

    # Empty candidate list is a whole-request error.
    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

        # Files must be an object.
        # Empty object is allowed here because it is a candidate-level
        # invalid manifest, not a whole-request error.
        if not isinstance(
            candidate.get("files"),
            dict
        ):
            return False

    if len(names) != len(set(names)):
        return False

    return True


# ---------------------------------------------------------
# Freeze
# ---------------------------------------------------------

def perform_freeze(body):

    freeze_id = body["freezeId"]

    # Existing freeze ID.
    if freeze_id in FREEZES:

        existing = FREEZES[freeze_id]

        # Exact replay.
        if existing["request"] == body:
            return existing["response"], 200

        # Different request using same ID.
        return {
            "error": "FREEZE_ID_CONFLICT"
        }, 409

    calibration_digest = body[
        "calibrationDigest"
    ]

    tokenizer_digest = body[
        "tokenizerDigest"
    ]

    allowed_reasons = set(
        body["allowedUnsupportedReasons"]
    )

    output = []

    for candidate in body["candidates"]:

        name = candidate["name"]

        files = candidate["files"]

        inventory_result = build_inventory(files)

        # Candidate has malformed files.
        if inventory_result is None:

            output.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": [],
                    "totalBytes": None,
                    "packageDigest": None,
                    "reasonCodes": [
                        "INVALID_INPUT"
                    ],
                }
            )

            continue

        inventory, total_bytes, package_digest = (
            inventory_result
        )

        # Empty files object is a candidate-level
        # invalid manifest.
        if inventory == []:

            output.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": [],
                    "totalBytes": None,
                    "packageDigest": None,
                    "reasonCodes": [
                        "INVALID_INPUT"
                    ],
                }
            )

            continue

        reasons = []

        unsupported_reason = candidate.get(
            "unsupportedReason"
        )

        # -------------------------------------------------
        # Unsupported candidate
        # -------------------------------------------------

        if unsupported_reason is not None:

            if (
                not nonempty_string(
                    unsupported_reason
                )
                or unsupported_reason
                not in allowed_reasons
            ):
                reasons.append(
                    "UNALLOWED_UNSUPPORTED_REASON"
                )

            else:
                output.append(
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

        # -------------------------------------------------
        # Normal candidate
        # -------------------------------------------------

        if candidate.get("loadable") is not True:
            reasons.append(
                "NOT_LOADABLE"
            )

        if (
            candidate.get(
                "calibrationDigest"
            )
            != calibration_digest
        ):
            reasons.append(
                "CALIBRATION_MISMATCH"
            )

        if (
            candidate.get(
                "tokenizerDigest"
            )
            != tokenizer_digest
        ):
            reasons.append(
                "TOKENIZER_MISMATCH"
            )

        reasons = sorted_codes(reasons)

        if reasons:

            output.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": reasons,
                }
            )

        else:

            output.append(
                {
                    "name": name,
                    "status": "frozen",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": [],
                }
            )

    # Required UTF-8 name ordering.
    output.sort(
        key=lambda item: utf8_key(item["name"])
    )

    response = {
        "freezeId": freeze_id,
        "candidates": output,
    }

    # Only valid freeze requests reserve the ID.
    FREEZES[freeze_id] = {
        "request": body,
        "response": response,
    }

    return response, 200


# ---------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------

def validate_manifest(manifest):

    if not isinstance(manifest, dict):
        return False

    required = [
        "name",
        "status",
        "inventory",
        "totalBytes",
        "packageDigest",
        "reasonCodes",
    ]

    for key in required:
        if key not in manifest:
            return False

    inventory = manifest["inventory"]

    if not isinstance(inventory, list):
        return False

    names = set()
    rebuilt = []

    for item in inventory:

        if not isinstance(item, dict):
            return False

        name = item.get("name")
        bytes_value = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return False

        if name in names:
            return False

        names.add(name)

        if not safe_integer(bytes_value):
            return False

        if (
            not isinstance(digest, str)
            or len(digest) != 64
        ):
            return False

        try:
            int(digest, 16)
        except ValueError:
            return False

        rebuilt.append(
            {
                "name": name,
                "bytes": bytes_value,
                "sha256": digest,
            }
        )

    rebuilt.sort(
        key=lambda item: utf8_key(item["name"])
    )

    if rebuilt != inventory:
        return False

    total = sum(
        item["bytes"]
        for item in inventory
    )

    if manifest["totalBytes"] != total:
        return False

    digest = sha256_bytes(
        compact_json(inventory)
    )

    if manifest["packageDigest"] != digest:
        return False

    return True


# ---------------------------------------------------------
# Policy validation
# ---------------------------------------------------------

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    if not finite_floor(
        policy.get("aggregateFloor")
    ):
        return False

    if not finite_nonnegative(
        policy.get("maxLatencyMs")
    ):
        return False

    required_slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(
        required_slices,
        dict
    ):
        return False

    for slice_name, floor in (
        required_slices.items()
    ):

        if not nonempty_string(slice_name):
            return False

        if not finite_floor(floor):
            return False

    order = policy.get(
        "candidateOrder"
    )

    if not unique_strings(order):
        return False

    return True


# ---------------------------------------------------------
# Prediction metrics
# ---------------------------------------------------------

def calculate_metrics(
    candidate_name,
    rows,
):

    if not isinstance(rows, list):
        return None, None, False

    if len(rows) == 0:
        return None, {}, False

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            return None, {}, False

        if "label" not in row:
            return None, {}, False

        label = row["label"]

        if not binary_value(label):
            return None, {}, False

        predictions = row.get(
            "predictions"
        )

        if not isinstance(
            predictions,
            dict
        ):
            return None, {}, False

        if candidate_name not in predictions:
            return None, {}, False

        prediction = predictions[
            candidate_name
        ]

        if not binary_value(prediction):
            return None, {}, False

        if prediction == label:
            correct += 1

        slice_name = row.get("slice")

        if not nonempty_string(slice_name):
            return None, {}, False

        if slice_name not in slice_total:
            slice_total[slice_name] = 0
            slice_correct[slice_name] = 0

        slice_total[slice_name] += 1

        if prediction == label:
            slice_correct[slice_name] += 1

    aggregate = round(
        correct / len(rows),
        12,
    )

    slices = {}

    for slice_name in sorted(
        slice_total,
        key=utf8_key,
    ):

        slices[slice_name] = round(
            slice_correct[slice_name]
            / slice_total[slice_name],
            12,
        )

    return aggregate, slices, True


# ---------------------------------------------------------
# Selection
# ---------------------------------------------------------

def perform_select(body):

    freeze_id = body.get(
        "freezeId"
    )

    stored = FREEZES.get(
        freeze_id
    )

    # Unknown freeze.
    if stored is None:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    supplied_candidates = body[
        "candidates"
    ]

    rows = body["rows"]

    policy = body["policy"]

    stored_candidates = (
        stored["response"]["candidates"]
    )

    stored_names = [
        item["name"]
        for item in stored_candidates
    ]

    supplied_names = [
        item.get("name")
        if isinstance(item, dict)
        else None
        for item in supplied_candidates
    ]

    # Exact frozen candidate response required.
    invalid_lineage = (
        supplied_candidates
        != stored_candidates
    )

    if (
        len(supplied_names)
        != len(stored_names)
    ):
        invalid_lineage = True

    if (
        len(set(supplied_names))
        != len(supplied_names)
    ):
        invalid_lineage = True

    if set(supplied_names) != set(
        stored_names
    ):
        invalid_lineage = True

    invalid_policy = not validate_policy(
        policy
    )

    order = policy.get(
        "candidateOrder",
        []
    )

    if not invalid_policy:

        if len(order) != len(
            stored_names
        ):
            invalid_policy = True

        elif len(set(order)) != len(
            order
        ):
            invalid_policy = True

        elif set(order) != set(
            stored_names
        ):
            invalid_policy = True

    latencies = body.get(
        "latencies"
    )

    if not isinstance(
        latencies,
        dict
    ):
        invalid_policy = True

    frozen_by_name = {
        item["name"]: item
        for item in stored_candidates
    }

    results = []

    for candidate in supplied_candidates:

        name = (
            candidate.get("name")
            if isinstance(
                candidate,
                dict,
            )
            else None
        )

        reasons = []

        if invalid_lineage:
            reasons.append(
                "INVALID_LINEAGE"
            )

        if invalid_policy:
            reasons.append(
                "INVALID_POLICY"
            )

        record = frozen_by_name.get(
            name
        )

        # Candidate must exactly equal the
        # recorded frozen manifest.
        manifest_valid = (
            record is not None
            and isinstance(
                candidate,
                dict,
            )
            and candidate == record
            and validate_manifest(
                candidate
            )
        )

        if not manifest_valid:
            reasons.append(
                "INVALID_MANIFEST"
            )

        aggregate, slices, predictions_valid = (
            calculate_metrics(
                name,
                rows,
            )
        )

        if not predictions_valid:
            reasons.append(
                "INVALID_PREDICTIONS"
            )

        total_bytes = None

        if manifest_valid:
            total_bytes = record[
                "totalBytes"
            ]

        latency_ms = None

        if (
            isinstance(
                latencies,
                dict
            )
            and name in latencies
        ):

            latency_value = latencies[
                name
            ]

            if finite_nonnegative(
                latency_value
            ):
                latency_ms = latency_value

        # ---------------------------------------------
        # Constraint checks
        # ---------------------------------------------

        if (
            not invalid_policy
            and predictions_valid
        ):

            if (
                aggregate
                < policy[
                    "aggregateFloor"
                ]
            ):
                reasons.append(
                    "AGGREGATE_FLOOR"
                )

            for (
                slice_name,
                floor,
            ) in policy[
                "requiredSlices"
            ].items():

                if slice_name not in slices:

                    reasons.append(
                        "MISSING_SLICE:"
                        + slice_name
                    )

                elif (
                    slices[slice_name]
                    < floor
                ):

                    reasons.append(
                        "SLICE_FLOOR:"
                        + slice_name
                    )

            if (
                total_bytes is not None
                and total_bytes
                > policy["maxBytes"]
            ):

                reasons.append(
                    "SIZE_LIMIT"
                )

            if (
                latency_ms is not None
                and latency_ms
                > policy["maxLatencyMs"]
            ):

                reasons.append(
                    "LATENCY_LIMIT"
                )

        # Only frozen candidates can win.
        if record is None:
            reasons.append(
                "INVALID_LINEAGE"
            )

        elif record["status"] != "frozen":
            reasons.append(
                "INVALID_LINEAGE"
            )

        reasons = sorted_codes(
            reasons
        )

        admitted = (
            len(reasons) == 0
        )

        results.append(
            {
                "name": name,
                "aggregate": aggregate,
                "slices": (
                    slices
                    if predictions_valid
                    else {}
                ),
                "totalBytes": total_bytes,
                "latencyMs": latency_ms,
                "admitted": admitted,
                "reasonCodes": reasons,
            }
        )

    # ---------------------------------------------
    # Result ordering
    # ---------------------------------------------

    order_index = {
        name: index
        for index, name
        in enumerate(order)
    }

    results.sort(
        key=lambda item: (
            order_index.get(
                item["name"],
                len(order),
            ),
            utf8_key(
                item["name"]
                if isinstance(
                    item["name"],
                    str,
                )
                else ""
            ),
        )
    )

    # ---------------------------------------------
    # Winner
    # ---------------------------------------------

    admitted = [
        item
        for item in results
        if item["admitted"]
    ]

    selected = None
    package_manifest = None

    if admitted:

        winner = min(
            admitted,
            key=lambda item: (
                item["totalBytes"],
                float(
                    item["latencyMs"]
                ),
                order_index.get(
                    item["name"],
                    len(order),
                ),
                utf8_key(
                    item["name"]
                ),
            ),
        )

        selected = winner[
            "name"
        ]

        package_manifest = (
            frozen_by_name[
                selected
            ]
        )

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }, 200


# ---------------------------------------------------------
# API endpoint
# ---------------------------------------------------------

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()

    except Exception:

        return JSONResponse(
            {
                "error":
                "INVALID_INPUT"
            },
            status_code=400,
        )

    if not isinstance(
        body,
        dict,
    ):

        return JSONResponse(
            {
                "error":
                "INVALID_INPUT"
            },
            status_code=400,
        )

    phase = body.get(
        "phase"
    )

    # ---------------------------------------------
    # FREEZE
    # ---------------------------------------------

    if phase == "freeze":

        if not valid_freeze_request(
            body
        ):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400,
            )

        response, status = (
            perform_freeze(
                body
            )
        )

        return JSONResponse(
            response,
            status_code=status,
        )

    # ---------------------------------------------
    # SELECT
    # ---------------------------------------------

    if phase == "select":

        # The assignment requires these three
        # fields and their corresponding types.
        if (
            not isinstance(
                body.get(
                    "candidates"
                ),
                list,
            )
            or not isinstance(
                body.get(
                    "rows"
                ),
                list,
            )
            or not isinstance(
                body.get(
                    "policy"
                ),
                dict,
            )
        ):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400,
            )

        response, status = (
            perform_select(
                body
            )
        )

        return JSONResponse(
            response,
            status_code=status,
        )

    # Unknown / missing phase.
    return JSONResponse(
        {
            "error":
            "INVALID_INPUT"
        },
        status_code=400,
    )


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "status": "ok"
    }


@app.get("/healthz")
def healthz():
    return {
        "status": "ok"
    }
