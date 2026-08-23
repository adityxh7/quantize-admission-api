import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

# Stateful storage for frozen candidates.
FREEZES: dict[str, dict[str, Any]] = {}


# =========================================================
# BASIC HELPERS
# =========================================================

def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sorted_codes(codes: list[str]) -> list[str]:
    return sorted(set(codes), key=utf8_key)


def nonempty_string(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    if len(value) == 0:
        return False

    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False

    return True


def unique_strings(value: Any) -> bool:
    if not isinstance(value, list):
        return False

    if not all(nonempty_string(x) for x in value):
        return False

    return len(value) == len(set(value))


def safe_integer(value: Any) -> bool:
    return (
        type(value) is int
        and 0 <= value <= 9007199254740991
    )


def finite_nonnegative(value: Any) -> bool:
    return (
        (type(value) is int or type(value) is float)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def finite_floor(value: Any) -> bool:
    return (
        (type(value) is int or type(value) is float)
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def binary_value(value: Any) -> bool:
    # Only JSON integers 0 and 1 are valid.
    # True/False and 0.0/1.0 are rejected.
    return type(value) is int and value in (0, 1)


# =========================================================
# INVENTORY / PACKAGE DIGEST
# =========================================================

def build_inventory(files: Any):
    """
    Build:

        inventory
        totalBytes
        packageDigest

    Inventory items are exactly:

        {
            "name": "...",
            "bytes": 10,
            "sha256": "..."
        }

    Files are sorted by UTF-8 filename.
    """

    if not isinstance(files, dict):
        return None

    # Empty object = candidate-level invalid manifest.
    if len(files) == 0:
        return [], None, None

    inventory = []

    for filename, content in files.items():

        if not nonempty_string(filename):
            return None

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

    return (
        inventory,
        total_bytes,
        package_digest,
    )


def rebuild_manifest_inventory(inventory: Any):
    """
    Recompute totals and package digest from a submitted
    recorded inventory. This prevents trusting totalBytes
    or packageDigest supplied by the select request.
    """

    if not isinstance(inventory, list):
        return None

    if len(inventory) == 0:
        return None

    rebuilt = []
    names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return None

        name = item["name"]
        byte_count = item["bytes"]
        digest = item["sha256"]

        if not nonempty_string(name):
            return None

        if name in names:
            return None

        names.add(name)

        if not safe_integer(byte_count):
            return None

        if not isinstance(digest, str):
            return None

        if len(digest) != 64:
            return None

        if digest != digest.lower():
            return None

        try:
            int(digest, 16)
        except ValueError:
            return None

        rebuilt.append(
            {
                "name": name,
                "bytes": byte_count,
                "sha256": digest,
            }
        )

    rebuilt.sort(
        key=lambda item: utf8_key(item["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in rebuilt
    )

    package_digest = sha256_bytes(
        compact_json(rebuilt)
    )

    return (
        rebuilt,
        total_bytes,
        package_digest,
    )


# =========================================================
# FREEZE REQUEST VALIDATION
# =========================================================

def valid_freeze_request(body: Any) -> bool:

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

        if not isinstance(
            candidate.get("files"),
            dict,
        ):
            return False

    if len(names) != len(set(names)):
        return False

    return True


# =========================================================
# FREEZE
# =========================================================

def perform_freeze(body: dict[str, Any]):

    freeze_id = body["freezeId"]

    # Existing freeze ID.
    if freeze_id in FREEZES:

        existing = FREEZES[freeze_id]

        # Exact replay.
        if existing["request"] == body:
            return (
                existing["response"],
                200,
            )

        # Different request with same ID.
        return (
            {
                "error": "FREEZE_ID_CONFLICT"
            },
            409,
        )

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

        inventory_result = build_inventory(
            candidate["files"]
        )

        # Malformed candidate manifest.
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

        # Empty files object.
        if len(inventory) == 0:

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

        unsupported_reason = candidate.get(
            "unsupportedReason"
        )

        # =================================================
        # UNSUPPORTED CANDIDATE
        # =================================================

        if unsupported_reason is not None:

            if (
                not nonempty_string(
                    unsupported_reason
                )
                or unsupported_reason
                not in allowed_reasons
            ):

                output.append(
                    {
                        "name": name,
                        "status": "invalid",
                        "inventory": inventory,
                        "totalBytes": total_bytes,
                        "packageDigest": package_digest,
                        "reasonCodes": [
                            "UNALLOWED_UNSUPPORTED_REASON"
                        ],
                    }
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

        # =================================================
        # NORMAL CANDIDATE
        # =================================================

        reasons = []

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
        key=lambda item: utf8_key(
            item["name"]
        )
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


# =========================================================
# MANIFEST VALIDATION
# =========================================================

def validate_manifest(manifest: Any) -> bool:

    if not isinstance(manifest, dict):
        return False

    required = {
        "name",
        "status",
        "inventory",
        "totalBytes",
        "packageDigest",
        "reasonCodes",
    }

    if set(manifest.keys()) != required:
        return False

    if not nonempty_string(
        manifest["name"]
    ):
        return False

    if manifest["status"] not in {
        "frozen",
        "unsupported",
        "invalid",
    }:
        return False

    inventory = manifest["inventory"]

    if not isinstance(inventory, list):
        return False

    rebuilt = rebuild_manifest_inventory(
        inventory
    )

    if rebuilt is None:
        return False

    rebuilt_inventory, total_bytes, package_digest = (
        rebuilt
    )

    if manifest["inventory"] != rebuilt_inventory:
        return False

    if manifest["totalBytes"] != total_bytes:
        return False

    if manifest["packageDigest"] != package_digest:
        return False

    reason_codes = manifest["reasonCodes"]

    if not isinstance(
        reason_codes,
        list,
    ):
        return False

    if not all(
        nonempty_string(code)
        for code in reason_codes
    ):
        return False

    if (
        reason_codes
        != sorted_codes(reason_codes)
    ):
        return False

    return True


# =========================================================
# POLICY VALIDATION
# =========================================================

def validate_policy(policy: Any) -> bool:

    if not isinstance(policy, dict):
        return False

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if set(policy.keys()) != required:
        return False

    if not safe_integer(
        policy["maxBytes"]
    ):
        return False

    if not finite_floor(
        policy["aggregateFloor"]
    ):
        return False

    if not finite_nonnegative(
        policy["maxLatencyMs"]
    ):
        return False

    required_slices = policy[
        "requiredSlices"
    ]

    if not isinstance(
        required_slices,
        dict,
    ):
        return False

    for slice_name, floor in (
        required_slices.items()
    ):

        if not nonempty_string(
            slice_name
        ):
            return False

        if not finite_floor(floor):
            return False

    if not unique_strings(
        policy["candidateOrder"]
    ):
        return False

    return True


def validate_latencies(
    latencies: Any,
    candidate_names: list[str],
) -> bool:

    if not isinstance(
        latencies,
        dict,
    ):
        return False

    if set(latencies.keys()) != set(
        candidate_names
    ):
        return False

    for name in candidate_names:

        if not finite_nonnegative(
            latencies[name]
        ):
            return False

    return True


# =========================================================
# PREDICTIONS
# =========================================================

def calculate_metrics(
    candidate_name: str,
    rows: Any,
):

    if not isinstance(
        rows,
        list,
    ):
        return None, {}, False

    if len(rows) == 0:
        return None, {}, False

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(
            row,
            dict,
        ):
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
            dict,
        ):
            return None, {}, False

        if candidate_name not in predictions:
            return None, {}, False

        prediction = predictions[
            candidate_name
        ]

        if not binary_value(prediction):
            return None, {}, False

        slice_name = row.get(
            "slice"
        )

        if not nonempty_string(
            slice_name
        ):
            return None, {}, False

        if prediction == label:
            correct += 1

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

    return (
        aggregate,
        slices,
        True,
    )


# =========================================================
# SELECT
# =========================================================

def perform_select(
    body: dict[str, Any]
):

    freeze_id = body.get(
        "freezeId"
    )

    stored = FREEZES.get(
        freeze_id
    )

    # Unknown freeze ID.
    if stored is None:

        return (
            {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            },
            200,
        )

    supplied_candidates = body[
        "candidates"
    ]

    rows = body[
        "rows"
    ]

    policy = body[
        "policy"
    ]

    latencies = body.get(
        "latencies"
    )

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

    # =====================================================
    # LINEAGE
    # =====================================================

    invalid_lineage = (
        supplied_candidates
        != stored_candidates
    )

    if (
        len(supplied_candidates)
        != len(stored_candidates)
    ):
        invalid_lineage = True

    if (
        len(supplied_names)
        != len(set(supplied_names))
    ):
        invalid_lineage = True

    if (
        set(supplied_names)
        != set(stored_names)
    ):
        invalid_lineage = True

    # =====================================================
    # POLICY
    # =====================================================

    invalid_policy = not validate_policy(
        policy
    )

    order = []

    if not invalid_policy:

        order = policy[
            "candidateOrder"
        ]

        if (
            len(order)
            != len(stored_names)
        ):
            invalid_policy = True

        elif (
            len(set(order))
            != len(order)
        ):
            invalid_policy = True

        elif (
            set(order)
            != set(stored_names)
        ):
            invalid_policy = True

        if not validate_latencies(
            latencies,
            stored_names,
        ):
            invalid_policy = True

    frozen_by_name = {
        item["name"]: item
        for item in stored_candidates
    }

    results = []

    # =====================================================
    # EVALUATE EVERY CANDIDATE
    # =====================================================

    for candidate in supplied_candidates:

        name = (
            candidate.get("name")
            if isinstance(candidate, dict)
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

        # =================================================
        # MANIFEST
        # =================================================

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

        if manifest_valid:

            rebuilt = rebuild_manifest_inventory(
                candidate["inventory"]
            )

            if rebuilt is None:
                manifest_valid = False

            else:

                (
                    rebuilt_inventory,
                    rebuilt_total,
                    rebuilt_digest,
                ) = rebuilt

                if (
                    rebuilt_inventory
                    != candidate["inventory"]
                ):
                    manifest_valid = False

                if (
                    rebuilt_total
                    != candidate["totalBytes"]
                ):
                    manifest_valid = False

                if (
                    rebuilt_digest
                    != candidate["packageDigest"]
                ):
                    manifest_valid = False

        if not manifest_valid:
            reasons.append(
                "INVALID_MANIFEST"
            )

        # =================================================
        # PREDICTIONS
        # =================================================

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

        # =================================================
        # SIZE
        # =================================================

        total_bytes = None

        if manifest_valid:
            total_bytes = candidate[
                "totalBytes"
            ]

        # =================================================
        # LATENCY
        # =================================================

        latency_ms = None

        if (
            not invalid_policy
            and isinstance(
                latencies,
                dict,
            )
            and name in latencies
            and finite_nonnegative(
                latencies[name]
            )
        ):
            latency_ms = latencies[
                name
            ]

        # =================================================
        # CONSTRAINTS
        # =================================================

        if (
            not invalid_policy
            and predictions_valid
        ):

            # Aggregate floor.
            if (
                aggregate
                < policy[
                    "aggregateFloor"
                ]
            ):
                reasons.append(
                    "AGGREGATE_FLOOR"
                )

            # Required slices.
            for (
                slice_name,
                floor,
            ) in policy[
                "requiredSlices"
            ].items():

                if (
                    slice_name
                    not in slices
                ):

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

            # Size.
            if total_bytes is None:

                reasons.append(
                    "INVALID_MANIFEST"
                )

            elif (
                total_bytes
                > policy["maxBytes"]
            ):

                reasons.append(
                    "SIZE_LIMIT"
                )

            # Latency.
            if latency_ms is None:

                reasons.append(
                    "INVALID_POLICY"
                )

            elif (
                latency_ms
                > policy[
                    "maxLatencyMs"
                ]
            ):

                reasons.append(
                    "LATENCY_LIMIT"
                )

        # =================================================
        # ONLY FROZEN CANDIDATES CAN WIN
        # =================================================

        if (
            record is None
            or record["status"]
            != "frozen"
        ):

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

    # =====================================================
    # RESULT ORDER
    # =====================================================

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

    # =====================================================
    # WINNER
    # =====================================================

    admitted_candidates = [
        item
        for item in results
        if item["admitted"]
    ]

    selected = None
    package_manifest = None

    if admitted_candidates:

        winner = min(
            admitted_candidates,
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

    return (
        {
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest": package_manifest,
        },
        200,
    )


# =========================================================
# API
# =========================================================

@app.post("/quantize")
async def quantize(
    request: Request,
):

    try:
        body = await request.json()

    except Exception:

        return JSONResponse(
            {
                "error": "INVALID_INPUT"
            },
            status_code=400,
        )

    if not isinstance(
        body,
        dict,
    ):

        return JSONResponse(
            {
                "error": "INVALID_INPUT"
            },
            status_code=400,
        )

    phase = body.get(
        "phase"
    )

    # =====================================================
    # FREEZE
    # =====================================================

    if phase == "freeze":

        if not valid_freeze_request(
            body
        ):

            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400,
            )

        response, status = perform_freeze(
            body
        )

        return JSONResponse(
            response,
            status_code=status,
        )

    # =====================================================
    # SELECT
    # =====================================================

    if phase == "select":

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
                    "error": "INVALID_INPUT"
                },
                status_code=400,
            )

        response, status = perform_select(
            body
        )

        return JSONResponse(
            response,
            status_code=status,
        )

    # =====================================================
    # UNKNOWN / MISSING PHASE
    # =====================================================

    return JSONResponse(
        {
            "error": "INVALID_INPUT"
        },
        status_code=400,
    )


# =========================================================
# HEALTH
# =========================================================

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