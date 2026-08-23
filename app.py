import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

# Stateful storage for frozen requests.
FREEZES: dict[str, dict[str, Any]] = {}


# =========================================================
# HELPERS
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
    # Only integer 0 and 1 are valid binary values.
    # True/False and 0.0/1.0 are rejected.
    return type(value) is int and value in (0, 1)


# =========================================================
# INVENTORY
# =========================================================

def build_inventory(files: Any):
    """
    Build the exact inventory required by the specification.

    Returns:
        inventory, totalBytes, packageDigest

    None means the files object itself is malformed.

    Empty files object is treated as a candidate-level
    invalid manifest.
    """

    if not isinstance(files, dict):
        return None

    if len(files) == 0:
        return [], None, None

    inventory = []
    names = set()

    for filename, content in files.items():

        if not nonempty_string(filename):
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

    return (
        inventory,
        total_bytes,
        package_digest,
    )


def rebuild_inventory(inventory: Any):
    """
    Recompute inventory, totalBytes and packageDigest
    without trusting submitted aggregate fields.
    """

    if not isinstance(inventory, list):
        return None

    if len(inventory) == 0:
        return [], None, None

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
# FREEZE VALIDATION
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

    # Empty candidate list is a whole-request error.
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

        # IMPORTANT:
        # Do not reject the whole request because candidate.files
        # is malformed. Invalid candidate manifests are handled
        # at candidate level in perform_freeze().

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

        # Same ID with different input.
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
            candidate.get("files")
        )

        # Candidate-level invalid files.
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

        # =====================================================
        # UNSUPPORTED CANDIDATE
        # =====================================================

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

        # =====================================================
        # NORMAL CANDIDATE
        # =====================================================

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

        output.append(
            {
                "name": name,
                "status": (
                    "invalid"
                    if reasons
                    else "frozen"
                ),
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": reasons,
            }
        )

    # Sort candidates by UTF-8 name.
    output.sort(
        key=lambda item: utf8_key(
            item["name"]
        )
    )

    response = {
        "freezeId": freeze_id,
        "candidates": output,
    }

    # Persist complete response.
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

    rebuilt = rebuild_inventory(
        manifest["inventory"]
    )

    if rebuilt is None:
        return False

    (
        rebuilt_inventory,
        rebuilt_total,
        rebuilt_digest,
    ) = rebuilt

    if (
        manifest["inventory"]
        != rebuilt_inventory
    ):
        return False

    if (
        manifest["totalBytes"]
        != rebuilt_total
    ):
        return False

    if (
        manifest["packageDigest"]
        != rebuilt_digest
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

        if not finite_floor(
            floor
        ):
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
# METRICS
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

        if not binary_value(
            prediction
        ):
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

        slice_total[slice_name] = (
            slice_total.get(
                slice_name,
                0,
            )
            + 1
        )

        slice_correct[slice_name] = (
            slice_correct.get(
                slice_name,
                0,
            )
            + (
                1
                if prediction == label
                else 0
            )
        )

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

    # Unknown freeze.
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
        if isinstance(
            item,
            dict,
        )
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
            set(order)
            != set(stored_names)
        ):
            invalid_policy = True

        elif not validate_latencies(
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
    # CANDIDATE EVALUATION
    # =====================================================

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

        # Supplied candidate must exactly match
        # the recorded frozen response.
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

        # totalBytes is only returned when the manifest
        # can be validated.
        total_bytes = None

        if manifest_valid:
            total_bytes = candidate[
                "totalBytes"
            ]

        # latencyMs is only returned when it can be validated.
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

        # Only frozen candidates can win.
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
                float(item["latencyMs"]),
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
# API ENDPOINT
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

        # Assignment explicitly requires candidates and
        # rows to be arrays and policy to be an object.
        if (
            not isinstance(
                body.get("candidates"),
                list,
            )
            or not isinstance(
                body.get("rows"),
                list,
            )
            or not isinstance(
                body.get("policy"),
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