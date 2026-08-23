import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

# Stateful freeze storage.
# Render may restart the process, but within a running instance
# this preserves the required two-phase state.
FREEZES: dict[str, dict[str, Any]] = {}


# ============================================================
# BASIC HELPERS
# ============================================================

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
    return sorted(
        set(codes),
        key=utf8_key,
    )


def nonempty_string(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    if value == "":
        return False

    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False

    return True


def unique_nonempty_strings(value: Any) -> bool:
    if not isinstance(value, list):
        return False

    if any(
        not nonempty_string(item)
        for item in value
    ):
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


def valid_binary(value: Any) -> bool:
    # bool is intentionally rejected because True/False are not
    # binary prediction integers under this contract.
    return (
        type(value) is int
        and value in (0, 1)
    )


# ============================================================
# INVENTORY / PACKAGE DIGEST
# ============================================================

def build_inventory(files: Any):
    """
    Build:

      inventory
      totalBytes
      packageDigest

    Inventory is sorted by UTF-8 filename.

    packageDigest =
        SHA-256(
            UTF8(
                compact JSON.stringify(inventory)
            )
        )

    Returns None when the file object is malformed.
    """

    if not isinstance(files, dict):
        return None

    if len(files) == 0:
        return [], None, None

    inventory = []
    seen_names = set()

    for filename, text in files.items():

        if not isinstance(filename, str):
            return None

        if filename == "":
            return None

        if filename in seen_names:
            return None

        seen_names.add(filename)

        if not isinstance(text, str):
            return None

        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:
            return None

        inventory.append(
            {
                "name": filename,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    inventory.sort(
        key=lambda item: utf8_key(item["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = hashlib.sha256(
        compact_json(inventory)
    ).hexdigest()

    return (
        inventory,
        total_bytes,
        package_digest,
    )


def recompute_manifest_inventory(inventory: Any):
    """
    Validate/recompute a submitted inventory.

    The submitted totalBytes and packageDigest are never trusted.
    """

    if not isinstance(inventory, list):
        return None

    if len(inventory) == 0:
        return [], None, None

    rebuilt = []
    seen_names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return None

        if not {
            "name",
            "bytes",
            "sha256",
        }.issubset(item.keys()):
            return None

        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return None

        if name in seen_names:
            return None

        seen_names.add(name)

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

    package_digest = hashlib.sha256(
        compact_json(rebuilt)
    ).hexdigest()

    return (
        rebuilt,
        total_bytes,
        package_digest,
    )


# ============================================================
# FREEZE REQUEST VALIDATION
# ============================================================

def valid_freeze_request(body: Any) -> bool:

    if not isinstance(body, dict):
        return False

    # Explicit whole-request condition.
    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not nonempty_string(freeze_id):
        return False

    if len(freeze_id) > 128:
        return False

    calibration_digest = body.get(
        "calibrationDigest"
    )

    tokenizer_digest = body.get(
        "tokenizerDigest"
    )

    if not nonempty_string(
        calibration_digest
    ):
        return False

    if not nonempty_string(
        tokenizer_digest
    ):
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not unique_nonempty_strings(
        allowed
    ):
        return False

    candidates = body.get(
        "candidates"
    )

    # Explicit specification:
    # empty/non-array freeze candidates => HTTP 400.
    if not isinstance(
        candidates,
        list,
    ):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names are required to be non-empty and unique.
    names = []

    for candidate in candidates:

        if not isinstance(
            candidate,
            dict,
        ):
            return False

        name = candidate.get(
            "name"
        )

        if not nonempty_string(name):
            return False

        names.append(name)

    if len(names) != len(set(names)):
        return False

    return True


# ============================================================
# FREEZE
# ============================================================

def perform_freeze(
    body: dict[str, Any]
):

    freeze_id = body["freezeId"]

    # --------------------------------------------------------
    # Existing freeze ID
    # --------------------------------------------------------

    if freeze_id in FREEZES:

        stored = FREEZES[
            freeze_id
        ]

        # Identical replay.
        if stored["request"] == body:
            return (
                stored["response"],
                200,
            )

        # Same ID but different input.
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
        body[
            "allowedUnsupportedReasons"
        ]
    )

    results = []

    # --------------------------------------------------------
    # Process candidates
    # --------------------------------------------------------

    for candidate in body[
        "candidates"
    ]:

        name = candidate[
            "name"
        ]

        reasons = []

        inventory_result = build_inventory(
            candidate.get("files")
        )

        # ----------------------------------------------------
        # Invalid file object
        # ----------------------------------------------------

        if inventory_result is None:

            results.append(
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

        (
            inventory,
            total_bytes,
            package_digest,
        ) = inventory_result

        # ----------------------------------------------------
        # Empty file object
        # ----------------------------------------------------

        if len(inventory) == 0:

            results.append(
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

        # ----------------------------------------------------
        # Unsupported candidate
        # ----------------------------------------------------

        unsupported_reason = candidate.get(
            "unsupportedReason"
        )

        if unsupported_reason is not None:

            if (
                not nonempty_string(
                    unsupported_reason
                )
                or unsupported_reason
                not in allowed_reasons
            ):

                results.append(
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

                results.append(
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

        # ----------------------------------------------------
        # Normal candidate
        # ----------------------------------------------------

        if candidate.get(
            "loadable"
        ) is not True:

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

        reasons = sorted_codes(
            reasons
        )

        status = (
            "frozen"
            if len(reasons) == 0
            else "invalid"
        )

        results.append(
            {
                "name": name,
                "status": status,
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": reasons,
            }
        )

    # --------------------------------------------------------
    # Sort candidates by UTF-8 name.
    # --------------------------------------------------------

    results.sort(
        key=lambda item: utf8_key(
            item["name"]
        )
    )

    response = {
        "freezeId": freeze_id,
        "candidates": results,
    }

    # Persist complete response and original request.
    FREEZES[freeze_id] = {
        "request": body,
        "response": response,
    }

    return response, 200


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(
    manifest: Any
) -> bool:

    if not isinstance(
        manifest,
        dict,
    ):
        return False

    required = {
        "name",
        "status",
        "inventory",
        "totalBytes",
        "packageDigest",
        "reasonCodes",
    }

    if not required.issubset(
        manifest.keys()
    ):
        return False

    name = manifest.get(
        "name"
    )

    if not nonempty_string(name):
        return False

    status = manifest.get(
        "status"
    )

    if status not in {
        "frozen",
        "unsupported",
        "invalid",
    }:
        return False

    reason_codes = manifest.get(
        "reasonCodes"
    )

    if not isinstance(
        reason_codes,
        list,
    ):
        return False

    if any(
        not nonempty_string(code)
        for code in reason_codes
    ):
        return False

    if reason_codes != sorted_codes(
        reason_codes
    ):
        return False

    rebuilt = recompute_manifest_inventory(
        manifest.get("inventory")
    )

    if rebuilt is None:
        return False

    (
        rebuilt_inventory,
        rebuilt_total,
        rebuilt_digest,
    ) = rebuilt

    if (
        manifest.get("inventory")
        != rebuilt_inventory
    ):
        return False

    if (
        manifest.get("totalBytes")
        != rebuilt_total
    ):
        return False

    if (
        manifest.get("packageDigest")
        != rebuilt_digest
    ):
        return False

    return True


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(
    policy: Any
) -> bool:

    if not isinstance(
        policy,
        dict,
    ):
        return False

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    # Required keys must exist.
    # Extra keys are harmless.
    if not required.issubset(
        policy.keys()
    ):
        return False

    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    if not finite_floor(
        policy.get(
            "aggregateFloor"
        )
    ):
        return False

    if not finite_nonnegative(
        policy.get(
            "maxLatencyMs"
        )
    ):
        return False

    required_slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(
        required_slices,
        dict,
    ):
        return False

    for (
        slice_name,
        floor,
    ) in required_slices.items():

        if not nonempty_string(
            slice_name
        ):
            return False

        if not finite_floor(
            floor
        ):
            return False

    candidate_order = policy.get(
        "candidateOrder"
    )

    if not unique_nonempty_strings(
        candidate_order
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

    # The supplied latency map must cover every candidate.
    if set(latencies.keys()) != set(
        candidate_names
    ):
        return False

    for name in candidate_names:

        if not finite_nonnegative(
            latencies.get(name)
        ):
            return False

    return True


# ============================================================
# PREDICTION METRICS
# ============================================================

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

    slice_total: dict[str, int] = {}
    slice_correct: dict[str, int] = {}

    for row in rows:

        if not isinstance(
            row,
            dict,
        ):
            return None, {}, False

        if "label" not in row:
            return None, {}, False

        label = row[
            "label"
        ]

        if not valid_binary(
            label
        ):
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

        if not valid_binary(
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

        slice_total[
            slice_name
        ] = (
            slice_total.get(
                slice_name,
                0,
            )
            + 1
        )

        slice_correct[
            slice_name
        ] = (
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
        slice_total.keys(),
        key=utf8_key,
    ):

        slices[slice_name] = round(
            slice_correct[
                slice_name
            ]
            / slice_total[
                slice_name
            ],
            12,
        )

    return (
        aggregate,
        slices,
        True,
    )


# ============================================================
# SELECT
# ============================================================

def perform_select(
    body: dict[str, Any]
):

    freeze_id = body.get(
        "freezeId"
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

    # --------------------------------------------------------
    # Locate freeze
    # --------------------------------------------------------

    stored = FREEZES.get(
        freeze_id
    )

    # Unknown freeze.
    # We still evaluate every supplied candidate and return
    # NOT_FROZEN rather than silently returning an empty result.
    if stored is None:

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

            aggregate, slices, valid_predictions = (
                calculate_metrics(
                    name,
                    rows,
                )
            )

            reasons = [
                "NOT_FROZEN"
            ]

            if not valid_predictions:
                reasons.append(
                    "INVALID_PREDICTIONS"
                )

            results.append(
                {
                    "name": name,
                    "aggregate": aggregate,
                    "slices": (
                        slices
                        if valid_predictions
                        else {}
                    ),
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": sorted_codes(
                        reasons
                    ),
                }
            )

        return (
            {
                "freezeId": freeze_id,
                "selected": None,
                "results": results,
                "packageManifest": None,
            },
            200,
        )

    # --------------------------------------------------------
    # Stored candidates
    # --------------------------------------------------------

    stored_candidates = (
        stored["response"][
            "candidates"
        ]
    )

    stored_names = [
        candidate["name"]
        for candidate
        in stored_candidates
    ]

    supplied_names = []

    for candidate in supplied_candidates:

        if isinstance(
            candidate,
            dict,
        ):
            supplied_names.append(
                candidate.get("name")
            )
        else:
            supplied_names.append(
                None
            )

    # --------------------------------------------------------
    # Lineage
    # --------------------------------------------------------

    invalid_lineage = False

    # Exact array equality is required.
    if (
        supplied_candidates
        != stored_candidates
    ):
        invalid_lineage = True

    if len(
        supplied_candidates
    ) != len(
        stored_candidates
    ):
        invalid_lineage = True

    if len(
        supplied_names
    ) != len(
        set(supplied_names)
    ):
        invalid_lineage = True

    if set(
        supplied_names
    ) != set(
        stored_names
    ):
        invalid_lineage = True

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    invalid_policy = not validate_policy(
        policy
    )

    candidate_order = []

    if not invalid_policy:

        candidate_order = policy[
            "candidateOrder"
        ]

        if len(
            candidate_order
        ) != len(
            stored_names
        ):
            invalid_policy = True

        elif set(
            candidate_order
        ) != set(
            stored_names
        ):
            invalid_policy = True

        elif not validate_latencies(
            latencies,
            stored_names,
        ):
            invalid_policy = True

    order_index = {
        name: index
        for index, name
        in enumerate(
            candidate_order
        )
    }

    stored_by_name = {
        candidate["name"]: candidate
        for candidate
        in stored_candidates
    }

    results = []

    # ========================================================
    # EVALUATE EACH CANDIDATE
    # ========================================================

    for candidate in supplied_candidates:

        if isinstance(
            candidate,
            dict,
        ):
            name = candidate.get(
                "name"
            )
        else:
            name = None

        reasons = []

        # ----------------------------------------------------
        # Lineage
        # ----------------------------------------------------

        if invalid_lineage:
            reasons.append(
                "INVALID_LINEAGE"
            )

        # ----------------------------------------------------
        # Policy
        # ----------------------------------------------------

        if invalid_policy:
            reasons.append(
                "INVALID_POLICY"
            )

        stored_candidate = stored_by_name.get(
            name
        )

        # ----------------------------------------------------
        # Frozen / status
        # ----------------------------------------------------

        if (
            stored_candidate is None
            or stored_candidate.get(
                "status"
            ) != "frozen"
        ):
            reasons.append(
                "NOT_FROZEN"
            )

        # ----------------------------------------------------
        # Manifest
        # ----------------------------------------------------

        manifest_valid = False

        if (
            stored_candidate is not None
            and isinstance(
                candidate,
                dict,
            )
        ):

            # Recompute supplied inventory.
            rebuilt = recompute_manifest_inventory(
                candidate.get(
                    "inventory"
                )
            )

            if rebuilt is not None:

                (
                    rebuilt_inventory,
                    rebuilt_total,
                    rebuilt_digest,
                ) = rebuilt

                supplied_manifest_valid = (
                    candidate.get(
                        "inventory"
                    )
                    == rebuilt_inventory
                    and candidate.get(
                        "totalBytes"
                    )
                    == rebuilt_total
                    and candidate.get(
                        "packageDigest"
                    )
                    == rebuilt_digest
                )

                recorded_manifest_valid = (
                    validate_manifest(
                        stored_candidate
                    )
                )

                if (
                    supplied_manifest_valid
                    and recorded_manifest_valid
                    and candidate
                    == stored_candidate
                ):
                    manifest_valid = True

        if not manifest_valid:
            reasons.append(
                "INVALID_MANIFEST"
            )

        # ----------------------------------------------------
        # Predictions
        # ----------------------------------------------------

        (
            aggregate,
            slices,
            predictions_valid,
        ) = calculate_metrics(
            name,
            rows,
        )

        if not predictions_valid:
            reasons.append(
                "INVALID_PREDICTIONS"
            )

        # ----------------------------------------------------
        # totalBytes
        # ----------------------------------------------------

        total_bytes = None

        if manifest_valid:

            rebuilt = recompute_manifest_inventory(
                candidate["inventory"]
            )

            if rebuilt is not None:

                (
                    _,
                    total_bytes,
                    _,
                ) = rebuilt

        # ----------------------------------------------------
        # latencyMs
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Constraints
        # ----------------------------------------------------

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
                    slices[
                        slice_name
                    ]
                    < floor
                ):

                    reasons.append(
                        "SLICE_FLOOR:"
                        + slice_name
                    )

            # Size.
            if total_bytes is not None:

                if (
                    total_bytes
                    > policy[
                        "maxBytes"
                    ]
                ):

                    reasons.append(
                        "SIZE_LIMIT"
                    )

            # Latency.
            if latency_ms is not None:

                if (
                    latency_ms
                    > policy[
                        "maxLatencyMs"
                    ]
                ):

                    reasons.append(
                        "LATENCY_LIMIT"
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

    # ========================================================
    # ORDER RESULTS
    # ========================================================

    results.sort(
        key=lambda item: (
            order_index.get(
                item["name"],
                len(candidate_order),
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

    # ========================================================
    # CHOOSE WINNER
    # ========================================================

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
            key=lambda item: (
                item["totalBytes"],
                item["latencyMs"],
                order_index.get(
                    item["name"],
                    len(candidate_order),
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
            stored_by_name[
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


# ============================================================
# POST /quantize
# ============================================================

@app.post("/quantize")
async def quantize(
    request: Request
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

    # ========================================================
    # FREEZE
    # ========================================================

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

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Explicit specification:
        # candidates must be an array,
        # rows must be an array,
        # policy must be an object.
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

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    return JSONResponse(
        {
            "error": "INVALID_INPUT"
        },
        status_code=400,
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/healthz")
def healthz():
    return {
        "status": "ok"
    }


@app.get("/")
def root():
    return {
        "status": "ok"
    }