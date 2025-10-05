# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort, flash, make_response, current_app
import os
import io, zipfile
import json
import uuid
from datetime import datetime, timezone
# --- Heuristics integration imports ---
from werkzeug.utils import secure_filename
from modules import utils as mutils
from functools import wraps
from flask import session, redirect, url_for, request, jsonify

from modules.utils import (
    write_signed_metadata,
    verify_signed_metadata,
    hmac_for_obj,
    record_audit,
    ensure_case_dirs,
    atomic_write_json
)

import tempfile

from modules.models import ChainOfCustody

def _heuristics_stub(path, *args, **kwargs):
    return {"suspicion_score": None, "reasons": [], "component_scores": {}}

try:
    from heuristics import analyze_file
except Exception:
    analyze_file = _heuristics_stub


# utils for file saves (keeps existing behavior)
from modules.utils import save_uploaded_file, iso_time_now, add_coc_entry
from werkzeug.exceptions import RequestEntityTooLarge
from modules.hashing import compute_sha256, update_artifact_hash
from modules.ioc import check_iocs_for_artifact
from modules.yara import scan_artifact as yara_scan_artifact, compile_rules as yara_compile_rules
from modules import utils_events
from modules.reporting import register_reporting_routes

import shutil

# DB
from modules.db import db

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "evidence"
# ---------------------------
# App config: upload limits, allowed extensions & logging
# ---------------------------
# Max upload size: 100 MB (adjust as needed). This prevents huge uploads in demo.
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# Allowed extensions (None = allow all). Example: {'exe','dll','txt','log'}
ALLOWED_EXTENSIONS = None  # change to a set like {'exe','txt'} to restrict


# (optional) configure input file locations if not default
app.config['TIMELINE_PROCESSES_PATH'] = 'data/processes.csv'
app.config['TIMELINE_EVENTS_PATH'] = 'data/events.json'

# Setup basic logging
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cyber-triage")


# ---------------------------
# Robust DB path setup
# ---------------------------
# Use an absolute path for the SQLite file so the DB is always created under the project data/ folder.
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

db_path = os.path.join(DATA_DIR, "triage.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Ensure base evidence dir exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# init DB (db is defined in modules/db.py)
db.init_app(app)

# import models AFTER db.init_app to avoid circular import issues
with app.app_context():
    from modules import models  # registers models with SQLAlchemy
    # create tables if they don't exist
    db.create_all()
    Case = models.Case
    Artifact = models.Artifact

# Register reporting blueprint (for PDF + ZIP report downloads)
register_reporting_routes(app)

# --- safe import & register of timeline blueprint (idempotent) ---
# --- import timeline blueprint (do NOT register it yet; register after adding hooks) ---
try:
    from modules.timeline import bp as timeline_bp
except Exception:
    timeline_bp = None
    logger.exception("modules.timeline import failed; timeline routes will be disabled")


import re
CASE_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]+$')

import pytz
# --- AUTH helpers (add near other imports) ---
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import session, g

# Ensure a secret key is configured for session cookies
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# path for simple user store (dev use only)
USERS_JSON = os.path.join(DATA_DIR, "users.json")
os.makedirs(DATA_DIR, exist_ok=True)

# Custom Jinja filter to convert UTC → IST
@app.template_filter("ist_time")
def ist_time_filter(value):
    """
    Convert an ISO datetime string or datetime object (UTC) into IST (24h format).
    Example output: 04-10-2025 10:03:54 IST
    """
    if not value:
        return "-"
    try:
        if isinstance(value, str):
            # handle ISO8601 with Z
            if value.endswith("Z"):
                value = value[:-1]
            dt = datetime.fromisoformat(value)
        elif isinstance(value, datetime):
            dt = value
        else:
            return str(value)

        # assume UTC if naive
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.UTC)

        # convert to IST
        ist = pytz.timezone("Asia/Kolkata")
        dt_ist = dt.astimezone(ist)

        return dt_ist.strftime("%d-%m-%Y %H:%M:%S IST")
    except Exception:
        return str(value)

def safe_case_id(case_id):
    if not CASE_ID_RE.match(case_id):
        raise ValueError("Invalid case_id")
    return case_id


# -------------------------
# Manifest helpers (keeps existing JSON manifest side-by-side)
# -------------------------
def manifest_path_for_case(case_id):
    case_dir = os.path.join(app.config["UPLOAD_FOLDER"], case_id)
    return os.path.join(case_dir, "manifest.json")


def load_manifest(case_id):
    manifest_p = manifest_path_for_case(case_id)
    if os.path.exists(manifest_p):
        try:
            # verify hmac; verify_signed_metadata returns (ok, details)
            ok, details = verify_signed_metadata(manifest_p)
            if not ok:
                # record an audit event: manifest HMAC mismatch detected
                try:
                    record_audit(db, case_id, None, "system:verifier", "manifest_hmac_mismatch", details)
                except Exception:
                    logger.exception("Failed to record audit for manifest_hmac_mismatch for %s", case_id)
            # return manifest contents regardless (caller decides how to handle)
            with open(manifest_p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            # if verification failed unexpectedly, fallback to reading manifest and log
            logger.exception("Failed to verify manifest HMAC for %s; returning raw manifest", case_id)
            try:
                with open(manifest_p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                logger.exception("Failed to read manifest even after verification error for %s", case_id)
    # default empty manifest if missing or unreadable
    return {
        "case_id": case_id,
        "created_at": iso_time_now(),
        "artifacts": []
    }


def save_manifest(case_id, manifest):
    """
    Atomically write and sign manifest.json for a case to avoid partial-write races.
    """
    case_dir, _ = ensure_case_dirs(case_id)
    manifest_p = manifest_path_for_case(case_id)
    try:
        write_signed_metadata(manifest_p, manifest)
    except Exception:
        logger.exception("Failed to write & sign manifest atomically")
        # fallback: try cleanup whatever .tmp exists
        temp_path = manifest_p + ".tmp"
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        raise


def add_artifact_to_manifest(case_id, artifact_metadata):
    manifest = load_manifest(case_id)
    summary = {
        "artifact_id": artifact_metadata.get("artifact_id"),
        "original_filename": artifact_metadata.get("original_filename"),
        "saved_filename": artifact_metadata.get("saved_filename"),
        "saved_path": artifact_metadata.get("saved_path"),
        "uploaded_by": artifact_metadata.get("uploaded_by"),
        "uploaded_at": artifact_metadata.get("uploaded_at"),
        "size_bytes": artifact_metadata.get("size_bytes"),
        "analysis": artifact_metadata.get("analysis")
    }
    manifest["artifacts"].append(summary)
    save_manifest(case_id, manifest)
    return manifest

def load_users():
    """Return dict username -> user-dict {email, password_hash}"""
    try:
        if os.path.exists(USERS_JSON):
            with open(USERS_JSON, "r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception:
        logger.exception("Failed loading users.json")
    return {}

def save_users(users):
    try:
        tmp = USERS_JSON + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(users, fh, indent=2)
        os.replace(tmp, USERS_JSON)
    except Exception:
        logger.exception("Failed saving users.json")

def login_required(view_fn):
    """
    Protect a normal HTML route: redirect to /login if not authenticated.
    Preserves the requested path in ?next= so login can return the user.
    """
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            # preserve intended path so login can redirect back
            return redirect(url_for('login', next=request.path))
        return view_fn(*args, **kwargs)
    return wrapped


def api_login_required(view_fn):
    """
    Protect an API route that returns JSON: respond 401 with JSON instead of redirect.
    Use on endpoints that expect JSON (optional).
    """
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "authentication required"}), 401
        return view_fn(*args, **kwargs)
    return wrapped


# ---------- Add these helper functions near your manifest helpers ----------
def list_cases():
    """
    Return a list of available case IDs. Prefer DB rows; fallback to evidence/ and data/ folders.
    Always returns a list (possibly empty).
    """
    cases = []
    try:
        # prefer DB Case rows if available
        try:
            rows = Case.query.order_by(Case.created_at.desc()).all()
            for r in rows:
                # ensure we return plain strings (case_id)
                cid = getattr(r, "case_id", None)
                if cid:
                    cases.append(cid)
        except Exception:
            # DB might not be available; ignore and fallback
            pass

        # also supplement with any subfolders under evidence/ or data/
        for base in (app.config.get("UPLOAD_FOLDER", "evidence"), os.path.join(PROJECT_ROOT, "data")):
            try:
                if os.path.exists(base):
                    for name in sorted(os.listdir(base)):
                        p = os.path.join(base, name)
                        if os.path.isdir(p) and name not in cases:
                            cases.append(name)
            except Exception:
                continue
    except Exception:
        logger.exception("list_cases helper failed; returning []")
    # dedupe and return
    seen = set(); out = []
    for c in cases:
        if c and c not in seen:
            seen.add(c); out.append(c)
    return out


def _normalize_event(ev):
    """
    Ensure event is JSON-serializable and fields have consistent names:
      - timestamp -> ISO string in UTC (if present) or None
      - score -> numeric (prefer final_score or suspicion_score)
      - type, source, file_name, artifact_id, json -> stable keys
    """
    out = {}
    try:
        # timestamp normalization: accept ISO strings or datetime objects
        ts = ev.get("timestamp") or ev.get("ts") or ev.get("uploaded_at") or ev.get("time") or ev.get("ts_utc")
        if isinstance(ts, datetime):
            # ensure ISO and append Z as UTC marker if tzinfo None assume UTC
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            out["timestamp"] = ts.astimezone(timezone.utc).isoformat()
        elif isinstance(ts, str) and ts:
            # try to normalize simple strings
            s = ts
            # preserve as-is if it looks like ISO, else attempt safe conversion
            try:
                if s.endswith("Z"):
                    s2 = s
                else:
                    # attempt parse and reformat with ISO + Z
                    dt = datetime.fromisoformat(s)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    s2 = dt.astimezone(timezone.utc).isoformat()
                out["timestamp"] = s2
            except Exception:
                out["timestamp"] = s
        else:
            out["timestamp"] = None
    except Exception:
        out["timestamp"] = None

    # score: try several keys, coerce to number or None
    score = None
    try:
        for k in ("score", "final_score", "suspicion_score", "finalScore"):
            v = ev.get(k)
            if v is not None:
                try:
                    score = int(v)
                except Exception:
                    try:
                        score = float(v)
                    except Exception:
                        score = None
                break
    except Exception:
        score = None
    out["score"] = score if score is not None else 0

    # simple passthrough fields
    out["type"] = ev.get("type") or ev.get("event_type") or ev.get("action") or "event"
    out["source"] = ev.get("source") or ev.get("actor") or ev.get("uploader") or ev.get("provider") or None
    out["file_name"] = ev.get("file_name") or ev.get("original_filename") or ev.get("saved_filename") or ev.get("artifact_name") or None
    out["artifact_id"] = ev.get("artifact_id") or ev.get("id") or ev.get("artifact") and (ev.get("artifact").get("artifact_id") if isinstance(ev.get("artifact"), dict) else None) or None

    # keep a JSON-safe payload (small)
    payload = ev.get("details") or ev.get("analysis") or ev.get("payload") or ev.get("artifact") or {}
    try:
        # reduce large binary-ish fields; ensure serialization
        if isinstance(payload, (dict, list)) or payload is None:
            out["json"] = payload or {}
        else:
            out["json"] = {"value": str(payload)}
    except Exception:
        out["json"] = {}

    # include original raw event for debugging (lightweight)
    out["_raw_summary"] = {k: ev.get(k) for k in ("id", "type", "artifact_id") if ev.get(k) is not None}
    return out


def get_events_for_case(case_id, keep_na=False):
    """
    Robust loader for per-case events. Returns a list of normalized event dicts.
    - Reads data/<case_id>/events.json when available and normalizes entries.
    - If not present, tries to synthesize minimal events from manifest.json / DB artifacts.
    - Always returns a list (possibly empty).
    """
    safe = case_id
    out = []
    try:
        # 1) try data/<case_id>/events.json (common generated timeline)
        events_path = os.path.join("data", safe, "events.json")
        if os.path.exists(events_path):
            try:
                with open(events_path, "r", encoding="utf-8") as fh:
                    j = json.load(fh)
                # some timeline generators wrap under "timeline" or "timeline_preview"
                candidates = []
                if isinstance(j, dict):
                    # accept lists directly under known keys or the dict itself as a list if it is a list-like object
                    for key in ("timeline", "events", "timeline_preview", "items"):
                        if isinstance(j.get(key), list):
                            candidates = j.get(key)
                            break
                    # if still empty but dict contains list-ish entries, try j.get("events") fallback
                    if not candidates:
                        # maybe the top-level is already a list-shaped object keyed by something
                        # fallback: if j has "events" as dict with "items" member
                        if isinstance(j.get("events"), list):
                            candidates = j.get("events")
                if not candidates and isinstance(j, list):
                    candidates = j
                if not candidates and isinstance(j, dict):
                    # try to see if timeline_preview is a list
                    if isinstance(j.get("timeline_preview"), list):
                        candidates = j.get("timeline_preview")
                # if nothing found, treat top-level as list if possible
                if not candidates and isinstance(j, list):
                    candidates = j

                # normalize each candidate into a stable event shape
                for ev in (candidates or []):
                    if not isinstance(ev, dict):
                        continue
                    out.append(_normalize_event(ev))
                # if events were present, return them
                if out:
                    return out
            except Exception:
                logger.exception("Failed parsing events.json for %s", safe)

        # 2) fallback: synthesize events from manifest.json or DB artifact list
        manifest = load_manifest(safe)
        for art in manifest.get("artifacts", []) or []:
            ev = {
                "type": "artifact_manifest",
                "artifact_id": art.get("artifact_id") or art.get("saved_filename"),
                "original_filename": art.get("original_filename") or art.get("saved_filename"),
                "saved_path": art.get("saved_path"),
                "timestamp": art.get("uploaded_at") or art.get("created_at") or art.get("uploadedAt"),
                "score": art.get("suspicion_score") or (art.get("analysis") or {}).get("final_score"),
                "details": art.get("analysis") or {}
            }
            out.append(_normalize_event(ev))

        # 3) DB fallback: if manifest empty, use DB artifact rows (best-effort)
        if not out:
            try:
                arts = Artifact.query.filter_by(case_id=safe).order_by(Artifact.uploaded_at.asc()).all()
                for a in arts:
                    try:
                        d = a.to_dict() if hasattr(a, "to_dict") else {
                            "artifact_id": getattr(a, "artifact_id", None),
                            "original_filename": getattr(a, "original_filename", None),
                            "saved_filename": getattr(a, "saved_filename", None),
                            "uploaded_at": getattr(a, "uploaded_at").isoformat() + "Z" if getattr(a, "uploaded_at", None) else None,
                            "analysis": json.loads(getattr(a, "analysis")) if getattr(a, "analysis", None) else {}
                        }
                    except Exception:
                        d = {"artifact_id": getattr(a, "artifact_id", None), "original_filename": getattr(a, "original_filename", None)}
                    ev = {
                        "type": "artifact_db",
                        "artifact_id": d.get("artifact_id"),
                        "original_filename": d.get("original_filename"),
                        "timestamp": d.get("uploaded_at"),
                        "score": (d.get("analysis") or {}).get("final_score"),
                        "details": d.get("analysis") or {}
                    }
                    out.append(_normalize_event(ev))
            except Exception:
                # ignore DB errors
                logger.debug("DB fallback for events failed for %s", safe)
    except Exception:
        logger.exception("get_events_for_case failed for %s", case_id)

    # final guard: ensure list and JSON-serializable types
    final = []
    for e in out:
        try:
            # ensure 'json' field is a dict
            if not isinstance(e.get("json"), (dict, list)):
                e["json"] = {"value": str(e.get("json") or "")}
            # ensure score is numeric
            try:
                e["score"] = int(e.get("score")) if e.get("score") is not None else 0
            except Exception:
                try:
                    e["score"] = int(float(e.get("score")))
                except Exception:
                    e["score"] = 0
            final.append(e)
        except Exception:
            continue
    return final
# ---------- end helper functions ----------
# after: from modules.timeline import bp as timeline_bp
# BEFORE: app.register_blueprint(timeline_bp)

# protect everything inside the timeline blueprint
@timeline_bp.before_request
def require_login_for_timeline_bp():
    # allow blueprint static assets (if the blueprint registers static)
    if request.endpoint and request.endpoint.startswith(f"{timeline_bp.name}.static"):
        return None

    # allow any public endpoints you intentionally left on this blueprint
    # e.g. if you have timeline_bp.view_functions names to exempt:
    PUBLIC_TIMELINE_ENDPOINTS = {
        # f"{timeline_bp.name}.public_ping",
    }
    if request.endpoint in PUBLIC_TIMELINE_ENDPOINTS:
        return None

    # authenticated?
    if session.get("user"):
        return None

    # If the client expects JSON (AJAX/API), return 401 JSON instead of redirect.
    wants_json = request.accept_mimetypes.best in ("application/json", "application/javascript") or request.path.startswith("/api/")
    if wants_json:
        return jsonify({"error": "authentication required"}), 401

    # otherwise redirect to login and preserve next path
    return redirect(url_for("login", next=request.path))

# Now register the timeline blueprint (after the hook is attached)
if timeline_bp and timeline_bp.name not in app.blueprints:
    app.register_blueprint(timeline_bp)
    logger.debug("Timeline blueprint '%s' registered with login guard.", timeline_bp.name)

from modules.auth import bp as auth_bp
app.register_blueprint(auth_bp)
# -------------------------
# Routes
# -------------------------

@app.route("/")
def home():
    return render_template("home.html")

# Serve the upload form via GET so the browser can visit /upload
@app.route("/upload", methods=["GET"])
@login_required
def upload_page():
    # render the upload form template
    return render_template("upload.html")

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Save file to disk (modules.utils.save_uploaded_file), compute SHA-256,
    update manifest, and create/update DB records.
    Auto-runs IOC and YARA checks (if available) and refreshes response metadata.

    NEW: If the uploaded file is a ZIP archive, extract it and process every file inside:
    - extract to evidence/<case_id>/artifacts/uploads/zip_<stamp>/
    - for each extracted file: compute sha, run heuristics, IOC/YARA, compute final score
    - persist per-file artifact JSON and DB rows (re-using existing helpers)
    - generate case-level processes.csv and events.json (via generate_case_processes_and_events)
    - build timeline and return per-file scores + timeline preview
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    case_id = request.form.get("case_id", "case001").strip() or "case001"
    uploader = request.form.get("uploader", "investigator").strip() or "investigator"

    # 1) Save file to disk and write artifact JSON (existing behavior)
    try:
        metadata = save_uploaded_file(file, case_id=case_id, uploader=uploader, allowed_ext_set=ALLOWED_EXTENSIONS)
    except ValueError as ve:
        logger.warning("Upload blocked: %s", ve)
        return jsonify({"error": str(ve)}), 400
    except Exception:
        logger.exception("Upload failed while saving file")
        return jsonify({"error": "Failed to save uploaded file"}), 500

    # ensure manifest variable exists so later error-handling / returns don't NameError
    manifest = {}

    # Keep a manifest entry for the uploaded file itself (unchanged)
    try:
        manifest = add_artifact_to_manifest(case_id, metadata)
    except Exception:
        # log but do not let missing manifest blow up the whole upload flow
        logger.exception("Failed to update manifest after upload — continuing without manifest")
        # manifest stays as {} so later code can safely inspect it

    # -----------------------
    # Deduplication & immediate integrity handling (NEW)
    # -----------------------
    try:
        # compute sha256 (best-effort) right after save so we can dedupe before DB row creation
        saved_path = metadata.get("saved_path")
        sha256_hex = None
        bytes_total = None
        if saved_path and os.path.exists(saved_path):
            try:
                sha256_hex, bytes_total = compute_sha256(saved_path)
            except Exception:
                logger.exception("Failed to compute sha right after upload for %s", metadata.get("artifact_id"))

        if sha256_hex:
            metadata["sha256"] = sha256_hex

        # Try to detect duplicate across DB by SHA
        duplicate_found = None
        try:
            if sha256_hex:
                from modules.hashing import find_artifact_by_sha
                dup = find_artifact_by_sha(sha256_hex)
                if dup:
                    duplicate_found = {"artifact_id": dup.artifact_id, "case_id": dup.case_id, "db_id": getattr(dup, "id", None)}
        except Exception:
            logger.exception("Duplicate lookup failed for %s", metadata.get("artifact_id"))

        # Annotate on-disk artifact JSON and sign it atomically (robust version)
        try:
            _, artifacts_dir = ensure_case_dirs(case_id)
            meta_path = os.path.join(artifacts_dir, f"{metadata['artifact_id']}.json")

            # Defensive read (returns {} on missing/corrupt)
            on_disk_meta = mutils.load_signed_metadata_safe(meta_path)
            on_disk_meta = mutils.normalize_metadata_dict(on_disk_meta)

            # always set sha if present
            if sha256_hex:
                on_disk_meta["sha256"] = sha256_hex
                on_disk_meta.setdefault("analysis", {}).setdefault("integrity", [])
                on_disk_meta["analysis"]["latest_sha256"] = sha256_hex

            if duplicate_found:
                metadata["is_duplicate"] = True
                metadata["duplicate_of"] = duplicate_found["artifact_id"]
                on_disk_meta["is_duplicate"] = True
                on_disk_meta["duplicate_of"] = duplicate_found["artifact_id"]

                # sign and persist duplicate-marked metadata
                try:
                    mutils.write_signed_metadata(meta_path, on_disk_meta)
                except Exception:
                    logger.exception("mutils.write_signed_metadata failed when marking duplicate for %s", metadata.get("artifact_id"))
                    try:
                        mutils.atomic_write_json(meta_path, on_disk_meta)
                    except Exception:
                        logger.exception("Fallback atomic write failed when marking duplicate %s", metadata.get("artifact_id"))

                # audit duplicate detection
                try:
                    record_audit(db, case_id, metadata.get("artifact_id"), "system", "duplicate_detected",
                                 {"duplicate_of": duplicate_found["artifact_id"], "sha256": sha256_hex})
                except Exception:
                    logger.exception("Failed to write audit for duplicate_detected %s", metadata.get("artifact_id"))

            else:
                # not a duplicate -> persist sha and update DB via update_artifact_hash()
                try:
                    mutils.write_signed_metadata(meta_path, on_disk_meta)
                except Exception:
                    logger.exception("write_signed_metadata failed after upload for %s; attempting atomic write", metadata.get("artifact_id"))
                    try:
                        mutils.atomic_write_json(meta_path, on_disk_meta)
                    except Exception:
                        logger.exception("Fallback atomic write failed for sha write %s", metadata.get("artifact_id"))

                # update DB + append integrity history + audit
                try:
                    update_artifact_hash(case_id, metadata["artifact_id"], sha256_hex)
                except Exception:
                    logger.exception("update_artifact_hash failed for %s after upload", metadata.get("artifact_id"))

        except Exception:
            logger.exception("Failed annotating artifact JSON on disk for %s", metadata.get("artifact_id"))

    except Exception:
        logger.exception("Unexpected error during post-save dedupe/integrity handling")

    # --- ZIP file branch: detect and process archive contents ---
    try:
        saved_path = metadata.get("saved_path")
        is_zip = False
        # Only treat files explicitly ending with .zip as archives
        if saved_path and saved_path.lower().endswith(".zip"):
            is_zip = True


        if is_zip:
            logger.info("Zip upload detected; extracting and processing contents for case %s", case_id)

            # create an unpack dir under the artifacts dir so artifacts stay organized
            case_dir, artifacts_dir = ensure_case_dirs(case_id)
            import time
            stamp = str(int(time.time()))
            unpack_dir = os.path.join(artifacts_dir, "uploads", f"zip_{stamp}")
            os.makedirs(unpack_dir, exist_ok=True)

            # dynamic import of safe extractor (modules/zip_ingest.py)
            try:
                from modules.zip_ingest import safe_extract_zip
            except Exception:
                logger.exception("zip_ingest not available; cannot extract zip")
                return jsonify({"error": "zip extraction helper not available on server"}), 500

            try:
                extracted_paths = safe_extract_zip(saved_path, unpack_dir)
            except Exception as e:
                logger.exception("Zip extraction failed for %s: %s", saved_path, e)
                return jsonify({"error": "zip extraction failed", "exc": str(e)}), 500

            # Normalize any extracted metadata files into canonical per-artifact metadata
            try:
                # import here to avoid circular import at module import time
                from modules.ioc import normalize_extracted_metadata
                normalized_count = normalize_extracted_metadata(case_id)
                logger.info("Normalized %d extracted metadata files for case %s", normalized_count, case_id)
            except Exception:
                # don't abort processing if normalization fails; log and continue
                logger.exception("Failed to normalize extracted metadata for case %s", case_id)

            seen_extracted_ids = set()
            per_file_results = []
            for path in extracted_paths:
                try:
                    # compute sha
                    sha, _ = compute_sha256(path)

                    # run heuristics (best effort)
                    heur_report = {}
                    try:
                        heur_report = analyze_file(path)
                    except Exception:
                        logger.exception("Heuristics failed for %s", path)

                                        # Try to reuse any metadata produced by the extractor for this extracted file.
                    # If none found, fall back to creating a new extracted__<uuid> metadata object.
                    artifact_id = None
                    artifact_meta = None
                    dirpath = os.path.dirname(path)
                    basename = os.path.basename(path)

                    # Prefer a relative path *inside* the unpack dir so we keep package context
                    # unpack_dir is defined earlier in the ZIP branch; if not, fall back to basename
                    try:
                        relpath = os.path.relpath(path, unpack_dir)
                    except Exception:
                        relpath = basename

                    # Normalize relpath to use forward slashes for display consistency
                    relpath = relpath.replace(os.path.sep, "/")

                    try:
                        # 1) look for .json metadata in same directory
                        for fname in os.listdir(dirpath):
                            if not fname.lower().endswith(".json"):
                                continue
                            meta_candidate = os.path.join(dirpath, fname)
                            try:
                                with open(meta_candidate, "r", encoding="utf-8") as fh:
                                    cand = json.load(fh)
                            except Exception:
                                continue

                            if not isinstance(cand, dict):
                                continue

                            # Match metadata if it references the full relative path, the basename,
                            # or the saved_path (absolute)
                            if cand.get("saved_path") == path \
                            or cand.get("saved_filename") == basename \
                            or cand.get("original_filename") in (relpath, basename):
                                artifact_meta = cand
                                artifact_id = cand.get("artifact_id")
                                logger.info("Reusing metadata next to extracted file: %s -> %s", path, meta_candidate)
                                break

                            # If file is named extracted__<id>.json and contains artifact_id, use it
                            if fname.startswith("extracted__") and cand.get("artifact_id"):
                                artifact_meta = cand
                                artifact_id = cand.get("artifact_id")
                                logger.info("Found extracted__ metadata candidate next to file: %s -> %s", path, meta_candidate)
                                break

                        # 2) fallback: recursive search in artifacts dir for a json mentioning the relative path or basename
                        if not artifact_meta:
                            _, artifacts_dir = ensure_case_dirs(case_id)
                            for root, _, files in os.walk(artifacts_dir):
                                for fname in files:
                                    if not fname.lower().endswith(".json"):
                                        continue
                                    candpath = os.path.join(root, fname)
                                    try:
                                        with open(candpath, "r", encoding="utf-8") as fh:
                                            txt = fh.read()
                                    except Exception:
                                        continue
                                    # quick substring check; prefer relpath but allow basename hits
                                    if relpath in txt or basename in txt or fname.startswith("extracted__"):
                                        try:
                                            with open(candpath, "r", encoding="utf-8") as fh:
                                                cand = json.load(fh)
                                        except Exception:
                                            continue
                                        if isinstance(cand, dict) and cand.get("artifact_id"):
                                            artifact_meta = cand
                                            artifact_id = cand.get("artifact_id")
                                            logger.info("Reusing metadata found by content search: %s -> %s", path, candpath)
                                            break
                                if artifact_meta:
                                    break
                    except Exception:
                        logger.exception("Error while searching for existing metadata for extracted file %s", path)

                    # 3) if still not found, create a new artifact id/meta (fallback)
                    if not artifact_meta:
                        artifact_id = f"extracted__{uuid.uuid4().hex}"
                        artifact_meta = {
                            "artifact_id": artifact_id,
                            "original_filename": relpath,          # preserve folder context like "pkg1/manifest.json"
                            "saved_filename": basename,            # human-readable filename
                            "saved_path": path,
                            "uploaded_by": uploader,
                            "uploaded_at": iso_time_now(),
                            "size_bytes": os.path.getsize(path),
                        }
                    # ---- PATCH END ----
                                            # --- Ensure unique artifact_id for each extracted file ---
                    try:
                        # If artifact_id already exists in DB for this case, generate a new unique id.
                        # Also track ids we've created during this upload so we don't reuse them.
                        from modules.models import Artifact as DBArtifact

                        need_new_id = False
                        # If artifact_id already present in DB, we'll need a fresh id
                        try:
                            if artifact_id and Case.query.filter_by(case_id=case_id).first():
                                existing_row = DBArtifact.query.filter_by(artifact_id=artifact_id, case_id=case_id).first()
                                if existing_row:
                                    need_new_id = True
                        except Exception:
                            # DB might not be reachable here; fallback to checking seen_extracted_ids
                            pass

                        # Also avoid reusing an id created earlier in this same loop
                        if artifact_id in seen_extracted_ids:
                            need_new_id = True

                        if need_new_id or not artifact_id:
                            new_id = f"extracted__{uuid.uuid4().hex}"
                            # update artifact_meta in-memory
                            artifact_meta = artifact_meta or {}
                            artifact_meta['artifact_id'] = new_id
                            artifact_id = new_id
                            # write a per-file metadata JSON next to the extracted file so disk metadata matches the new id
                            try:
                                meta_path_new = os.path.join(os.path.dirname(path), f"{artifact_id}.json")
                                with open(meta_path_new, "w", encoding="utf-8") as fh_meta:
                                    json.dump(artifact_meta, fh_meta, indent=2)
                            except Exception:
                                logger.exception("Failed to write new per-extracted-file metadata for %s", path)
                        # record that we've used this id during this upload run
                        seen_extracted_ids.add(artifact_id)
                    except Exception:
                        logger.exception("Failed ensuring unique artifact_id for extracted file %s", path)

                        logger.debug("No pre-existing metadata found; created new artifact %s for %s", artifact_id, path)


                    # --- Ensure the artifact_meta keeps the correct filename/path for this extracted item ---
                    # prefer the relative path inside the unpack dir for display (relpath computed earlier)
                    try:
                        artifact_meta["original_filename"] = relpath
                        artifact_meta["saved_filename"] = basename
                        artifact_meta["saved_path"] = path
                    except Exception:
                        # defensive: if artifact_meta isn't a dict for any reason, recreate minimal metadata
                        artifact_meta = artifact_meta if isinstance(artifact_meta, dict) else {}
                        artifact_meta.update({
                            "artifact_id": artifact_id,
                            "original_filename": relpath,
                            "saved_filename": basename,
                            "saved_path": path,
                            "uploaded_by": uploader,
                            "uploaded_at": iso_time_now(),
                            "size_bytes": os.path.getsize(path),
                        })

                    # helpful debug log to confirm what will be written to DB/manifest
                    logger.info("Saving extracted artifact: %s (original=%s saved=%s)", artifact_meta.get("artifact_id"), artifact_meta.get("original_filename"), artifact_meta.get("saved_filename"))



                    # ===== SAFE: create or update DB record for this extracted file =====
                    try:
                        # ensure the case row exists
                        case_row = Case.query.filter_by(case_id=case_id).first()
                        if not case_row:
                            case_row = Case(case_id=case_id)
                            db.session.add(case_row)
                            try:
                                db.session.commit()
                            except Exception:
                                db.session.rollback()
                                logger.exception("Failed to create case row for %s", case_id)

                        # check if artifact already exists (avoid UNIQUE constraint errors)
                        existing_art = Artifact.query.filter_by(artifact_id=artifact_meta["artifact_id"], case_id=case_id).first()
                        if existing_art:
                            # update useful fields (do not blindly overwrite analysis)
                            existing_art.original_filename = artifact_meta.get("original_filename", existing_art.original_filename)
                            existing_art.saved_filename = artifact_meta.get("saved_filename", existing_art.saved_filename)
                            existing_art.saved_path = artifact_meta.get("saved_path", existing_art.saved_path)
                            existing_art.uploaded_by = artifact_meta.get("uploaded_by", existing_art.uploaded_by)
                            existing_art.size_bytes = artifact_meta.get("size_bytes", existing_art.size_bytes)
                            # only set uploaded_at if missing
                            if not existing_art.uploaded_at and artifact_meta.get("uploaded_at"):
                                try:
                                    existing_art.uploaded_at = datetime.fromisoformat(artifact_meta["uploaded_at"])
                                except Exception:
                                    existing_art.uploaded_at = datetime.now(timezone.utc)
                            db.session.add(existing_art)
                        else:
                            uploaded_at_dt = datetime.now(timezone.utc)
                            db_art = Artifact(
                                artifact_id=artifact_meta["artifact_id"],
                                case_id=case_id,
                                original_filename=artifact_meta.get("original_filename"),
                                saved_filename=artifact_meta.get("saved_filename"),
                                saved_path=artifact_meta.get("saved_path"),
                                uploaded_by=artifact_meta.get("uploaded_by"),
                                uploaded_at=uploaded_at_dt,
                                size_bytes=artifact_meta.get("size_bytes"),
                                analysis=None
                            )
                            db.session.add(db_art)

                        try:
                            db.session.commit()
                        except Exception:
                            db.session.rollback()
                            logger.exception("DB commit failed when creating/updating artifact %s for case %s",
                                             artifact_meta.get("artifact_id"), case_id)

                    except Exception:
                        try:
                            db.session.rollback()
                        except Exception:
                            pass
                        logger.exception("Failed to insert/update artifact record into DB for extracted file %s", path)

                    # update hash and run IOC/YARA using your existing helpers (artifact-based)
                    try:
                        update_artifact_hash(case_id, artifact_meta["artifact_id"], sha)
                    except Exception:
                        logger.exception("update_artifact_hash failed for %s", path)

                    ioc_matches = []
                    try:
                        ioc_res = check_iocs_for_artifact(case_id, artifact_meta["artifact_id"])
                        if isinstance(ioc_res, dict):
                            ioc_matches = ioc_res.get("matches", []) or []
                    except Exception:
                        logger.exception("IOC check failed for %s", path)

                    yara_matches = []
                    try:
                        yara_res = yara_scan_artifact(case_id, artifact_meta["artifact_id"])
                        if isinstance(yara_res, dict):
                            yara_matches = yara_res.get("matches", []) or []
                    except Exception:
                        logger.exception("YARA scan failed for %s", path)

                    # attach analysis & compute final score
                    artifact_meta["sha256"] = sha
                    artifact_meta["heuristics"] = heur_report
                    artifact_meta["ioc_matches"] = ioc_matches
                    artifact_meta["yara_matches"] = yara_matches

                    try:
                        from modules.scoring import compute_final_score
                        final = compute_final_score({
                            "ioc": ioc_matches,
                            "yara": yara_matches,
                            "heuristics": heur_report
                        })
                    except Exception:
                        logger.exception("compute_final_score failed for %s", path)
                        final = {"final_score": None, "breakdown": {}, "reasons": []}

                    artifact_meta["analysis"] = {
                        "final_score": final.get("final_score"),
                        "breakdown": final.get("breakdown"),
                        "reasons": final.get("reasons")
                    }

                    # persist artifact JSON next to file (signed & atomic, merge safely)
                    try:
                        meta_path = os.path.join(os.path.dirname(path), f"{artifact_meta['artifact_id']}.json")

                        # load existing (if any), normalize and merge to avoid clobbering
                        existing = mutils.load_signed_metadata_safe(meta_path)
                        existing = mutils.normalize_metadata_dict(existing)

                        # overlay top-level fields from artifact_meta (but don't copy any existing _meta)
                        existing.pop("_meta", None)
                        for k, v in (artifact_meta or {}).items():
                            if k == "_meta":
                                continue
                            existing[k] = v

                        # write & sign preferred, fallback to atomic
                        try:
                            mutils.write_signed_metadata(meta_path, existing)
                        except Exception:
                            logger.exception("Failed to write_signed_metadata for %s; attempting atomic write", path)
                            try:
                                mutils.atomic_write_json(meta_path, existing)
                            except Exception:
                                logger.exception("Fallback atomic write failed for artifact metadata %s", artifact_meta.get("artifact_id"))
                    except Exception:
                        logger.exception("Failed to write artifact metadata for %s", path)

                    # add to manifest (keeps existing behavior)
                    try:
                        add_artifact_to_manifest(case_id, artifact_meta)
                    except Exception:
                        logger.exception("Failed to add extracted artifact to manifest for %s", path)

                    per_file_results.append({
                        "artifact_id": artifact_meta["artifact_id"],
                        "filename": artifact_meta["original_filename"],
                        "sha256": sha,
                        "final_score": artifact_meta["analysis"]["final_score"],
                        "ioc_matches": ioc_matches,
                        "yara_matches": yara_matches
                    })

                    # --- publish a per-file event into data/<case_id>/events.json (non-destructive) ---
                    try:
                        # build compact artifact event for timeline
                        event_art = {
                            "artifact_id": artifact_meta["artifact_id"],
                            "original_filename": artifact_meta.get("original_filename"),
                            "saved_filename": artifact_meta.get("saved_filename"),
                            "saved_path": artifact_meta.get("saved_path"),
                            "size_bytes": artifact_meta.get("size_bytes"),
                            "uploaded_at": artifact_meta.get("uploaded_at"),
                            "uploaded_by": artifact_meta.get("uploaded_by"),
                            "analysis": {
                                "final_score": artifact_meta.get("analysis", {}).get("final_score"),
                                "reasons": artifact_meta.get("analysis", {}).get("reasons") if artifact_meta.get("analysis") else None
                            }
                        }
                        try:
                            utils_events.append_event(case_id, event_art)
                        except Exception:
                            # do not fail processing if events append fails
                            logger.exception("Failed to append per-file event for %s", artifact_meta.get("artifact_id"))
                    except Exception:
                        logger.exception("Error building/publishing per-file event for %s", artifact_meta.get("artifact_id"))

                except Exception as e:
                    logger.exception("Processing extracted file failed: %s", path)
                    per_file_results.append({"filename": path, "error": str(e)})

            # After processing all files -> generate case-level processes/events then build timeline
            case_data_dir = os.path.join("data", case_id)
            os.makedirs(case_data_dir, exist_ok=True)
            processes_path = os.path.join(case_data_dir, "processes.csv")
            events_path = os.path.join(case_data_dir, "events.json")

            # Ensure generator exists in timeline_utils
            # Use the canonical zip processor helper (process_extracted_files) to create data/<case>/processes.csv and events.json
            try:
                from modules.zip_ingest import process_extracted_files
            except Exception:
                process_extracted_files = None

            try:
                if process_extracted_files:
                    summary = process_extracted_files(case_id, extracted_paths)
                    logger.info("Case-level timeline files created: %s", summary)
                    try:
                        utils_events.append_event(case_id, {
                            "type": "zip_ingest",
                            "details": {
                                "processed_count": summary.get("processed"),
                                "csv_rows_written": summary.get("csv_rows_written"),
                                "events_appended": summary.get("events_appended")
                            }
                        })
                    except Exception:
                        logger.exception("Failed to append zip_ingest event for case %s", case_id)

                else:
                    logger.warning("No zip -> timeline processor available; skipping creation of case-level files.")
            except Exception:
                logger.exception("Failed creating case-level processes/events from extracted files")

            try:
                from modules.timeline import build_timeline
            except Exception:
                build_timeline = None
                logger.exception("timeline builder import failed; timeline will be skipped")


            try:
                if callable(build_timeline):
                    timeline = build_timeline(processes_path, events_path, keep_na=True)
                else:
                    logger.info("Timeline builder not available; skipping timeline build for case %s", case_id)
                    timeline = []
            except Exception:
                logger.exception("Failed building timeline after zip ingestion")
                timeline = []

            return jsonify({
                "status": "ok",
                "case_id": case_id,
                "files_processed": len(per_file_results),
                "per_file": per_file_results,
                "timeline_count": len(timeline),
                "timeline_preview": timeline[:10]
            })

    except Exception:
        # If anything unexpected happens in ZIP branch detection/processing, log and continue to single-file flow
        logger.exception("Unexpected error during ZIP handling; falling back to single-file processing")

    
    # 3) Write into DB: create Case if missing, then Artifact row
    try:
        case = Case.query.filter_by(case_id=case_id).first()
        if not case:
            case = Case(case_id=case_id)
            db.session.add(case)
            db.session.commit()  # commit to ensure case exists before FK use

        # Parse uploaded_at into datetime for DB (remove trailing Z)
        uploaded_at_str = metadata.get("uploaded_at")
        if uploaded_at_str and uploaded_at_str.endswith("Z"):
            uploaded_at_dt = datetime.fromisoformat(uploaded_at_str[:-1])
        else:
            uploaded_at_dt = datetime.utcnow()

        artifact = Artifact(
            artifact_id=metadata.get("artifact_id"),
            case_id=case_id,
            original_filename=metadata.get("original_filename"),
            saved_filename=metadata.get("saved_filename"),
            saved_path=metadata.get("saved_path"),
            uploaded_by=metadata.get("uploaded_by"),
            uploaded_at=uploaded_at_dt,
            size_bytes=metadata.get("size_bytes"),
            sha256=metadata.get("sha256"),  # may be None initially; set if computed earlier
            is_duplicate=bool(metadata.get("is_duplicate", False)),
            duplicate_of=metadata.get("duplicate_of"),
            analysis=json.dumps(metadata.get("analysis") or {})  # store empty dict rather than None for consistency
        )

        db.session.add(artifact)
        db.session.commit()
    except Exception:
        logger.exception("Failed to insert artifact record into DB")
        return jsonify({"error": "Failed to record artifact in database"}), 500

    # 4) Compute SHA-256, update artifact metadata + manifest + DB
    try:
        sha256_hex, _ = compute_sha256(metadata["saved_path"])
        update_artifact_hash(case_id, metadata["artifact_id"], sha256_hex)

        # --- NEW: record CoC entry for upload action ---
        try:
            from modules.utils import add_coc_entry
            add_coc_entry(db, case_id, metadata["artifact_id"], actor=metadata.get("uploaded_by", "uploader"), action="uploaded", location="uploader", details={"sha256": sha256_hex})
        except Exception:
            logger.exception("Failed to create CoC entry for upload %s/%s", case_id, metadata.get("artifact_id"))


        # add sha256 to the metadata that we return to the client
        metadata["sha256"] = sha256_hex

        # --- AUTO IOC CHECK (run immediately after hash update) ---
        try:
            try:
                ioc_result = check_iocs_for_artifact(case_id, metadata["artifact_id"])
                # attach to returned metadata for immediate visibility
                metadata["ioc_matches"] = ioc_result.get("matches", [])
            except FileNotFoundError as fe:
                logger.warning("IOC check: metadata/file not found for %s/%s: %s", case_id, metadata.get("artifact_id"), fe)
            except Exception:
                logger.exception("Auto IOC check failed for %s/%s", case_id, metadata.get("artifact_id"))
        except ImportError:
            # safety: if module import is somehow missing
            logger.info("IOC module not present; skipping auto IOC check")
        # --- end AUTO IOC CHECK ---

        # --- AUTO YARA SCAN (run after hash & IOC) ---
        try:
            try:
                yara_result = yara_scan_artifact(case_id, metadata["artifact_id"])
                # if yara module not available or compilation failed, yara_result will include an error
                if yara_result:
                    # attach yara result summary into the response metadata for immediate visibility
                    metadata["yara_matches"] = yara_result.get("matches", [])
                    # also include availability flag if present
                    if "yara_available" in yara_result:
                        metadata["yara_available"] = yara_result.get("yara_available")
            except Exception:
                logger.exception("Auto YARA scan failed for %s/%s", case_id, metadata.get("artifact_id"))
        except ImportError:
            logger.info("YARA module not present; skipping auto YARA scan")
        # --- end AUTO YARA ---

        # --- AUTO HEURISTICS ANALYSIS (new) ---
        try:
            try:
                heuristics_report = analyze_file(metadata["saved_path"])
                # attach heuristics to metadata for immediate visibility
                metadata["heuristics"] = heuristics_report

                # Persist heuristics report into DB Artifact.analysis (JSON) and artifact JSON file
                try:
                    # Save into DB artifact.analysis (merge with any existing analysis)
                    db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
                    if db_artifact:
                        # Merge existing analysis if present
                        existing = {}
                        try:
                            if db_artifact.analysis:
                                existing = json.loads(db_artifact.analysis) if isinstance(db_artifact.analysis, str) else db_artifact.analysis
                        except Exception:
                            existing = {}

                        # Attach heuristics under a key (keep other analysis like IOC/YARA)
                        existing.setdefault("heuristics", heuristics_report)
                        db_artifact.analysis = json.dumps(existing)
                        db.session.add(db_artifact)
                        db.session.commit()
                        # ensure metadata returned includes analysis
                        metadata["analysis"] = existing
                    else:
                        # If DB record missing (unlikely), fallback to writing artifact-side JSON
                        metadata["analysis"] = {"heuristics": heuristics_report}

                    # Also write to artifact JSON file adjacent to saved artifact (robust merge + sign)
                    meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                    try:

                        on_disk_meta = mutils.load_signed_metadata_safe(meta_path)
                        on_disk_meta = mutils.normalize_metadata_dict(on_disk_meta)

                        # merge heuristics into analysis safely
                        on_disk_meta.setdefault("analysis", {})
                        on_disk_meta["analysis"].setdefault("heuristics", heuristics_report)

                        try:
                            mutils.write_signed_metadata(meta_path, on_disk_meta)
                        except Exception:
                            logger.exception("Failed to write & sign heuristics artifact metadata for %s; attempting atomic write", metadata.get("artifact_id"))
                            try:
                                mutils.atomic_write_json(meta_path, on_disk_meta)
                            except Exception:
                                logger.exception("Fallback atomic write failed for heuristics metadata %s", metadata.get("artifact_id"))
                    except Exception:
                        logger.exception("Failed to write heuristics into artifact JSON on disk for %s", metadata.get("artifact_id"))
                except Exception:
                    logger.exception("Failed to persist heuristics analysis to DB for %s", metadata.get("artifact_id"))

            except Exception:
                logger.exception("Auto heuristics analysis failed for %s/%s", case_id, metadata.get("artifact_id"))
        except ImportError:
            # If import at top fails (shouldn't because you imported), log and continue
            logger.info("Heuristics module not present; skipping heuristics analysis")
        # --- end AUTO HEURISTICS ---


        # --- Update manifest.json with heuristics (new) ---
        try:
            m = load_manifest(case_id)
            # find artifact entry in manifest by artifact_id
            for entry in m.get("artifacts", []):
                if entry.get("artifact_id") == metadata.get("artifact_id"):
                    entry["analysis"] = metadata.get("analysis", entry.get("analysis"))
                    if metadata.get("heuristics"):
                        entry.setdefault("analysis", {})
                        entry["analysis"].setdefault("heuristics", metadata["heuristics"])
                        # also store suspicion_score at top-level for quick dashboard/summary use
                        entry["suspicion_score"] = metadata["heuristics"].get("suspicion_score")
                    break
            save_manifest(case_id, m)
        except Exception:
            logger.exception("Failed to update manifest.json with heuristics for %s", metadata.get("artifact_id"))
        # --- end manifest update ---

                # --- Compute final suspicion score combining IOC/YARA/HEURISTICS ---
        try:
            from modules.scoring import compute_final_score
            analysis_blob = metadata.get("analysis") or {}

            # run scoring (this normalizedly reads ioc/yara/heuristics)
            final = compute_final_score(analysis_blob)

            # attach results into metadata.analysis
            metadata.setdefault("analysis", {})
            metadata["analysis"]["final_score"] = final.get("final_score")
            metadata["analysis"]["final_breakdown"] = final.get("breakdown")
            metadata["analysis"]["final_reasons"] = final.get("reasons")

            # Persist into DB record (Artifact.analysis): merge with existing analysis
            try:
                db_art = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
                if db_art:
                    existing = {}
                    if db_art.analysis:
                        try:
                            existing = json.loads(db_art.analysis) if isinstance(db_art.analysis, str) else db_art.analysis
                        except Exception:
                            existing = {}
                    # merge/overwrite analysis keys with final score values
                    existing.update(metadata["analysis"])
                    db_art.analysis = json.dumps(existing)
                    db.session.add(db_art)
                    db.session.commit()
            except Exception:
                logger.exception("Failed to persist final score to DB for %s", metadata.get("artifact_id"))

            # Also update artifact JSON file (atomic write)
            # Also update artifact JSON file (signed preferred, atomic fallback)
            try:
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")

                on_disk_meta = mutils.load_signed_metadata_safe(meta_path)
                on_disk_meta = mutils.normalize_metadata_dict(on_disk_meta)


                # merge final analysis keys
                on_disk_meta.setdefault("analysis", {})
                if isinstance(metadata.get("analysis"), dict):
                    on_disk_meta["analysis"].update(metadata["analysis"])

                try:
                    mutils.write_signed_metadata(meta_path, on_disk_meta)
                except Exception:
                    logger.exception("Failed to write & sign final analysis metadata for %s; attempting atomic write", metadata.get("artifact_id"))
                    try:
                        mutils.atomic_write_json(meta_path, on_disk_meta)
                    except Exception:
                        logger.exception("Fallback atomic write failed for final analysis metadata %s", metadata.get("artifact_id"))
            except Exception:
                logger.exception("Failed to write final score into artifact JSON on disk for %s", metadata.get("artifact_id"))

            # Update manifest entry for this artifact (if present)
            try:
                m = load_manifest(case_id)
                changed = False
                for entry in m.get("artifacts", []):
                    if entry.get("artifact_id") == metadata.get("artifact_id"):
                        entry["analysis"] = metadata.get("analysis")
                        # also keep a top-level compatibility field used by UI
                        entry["suspicion_score"] = metadata["analysis"].get("final_score")
                        changed = True
                        break
                if changed:
                    save_manifest(case_id, m)
            except Exception:
                logger.exception("Failed to update manifest with final score for %s", metadata.get("artifact_id"))

        except Exception:
            logger.exception("Failed to compute/persist final suspicion score for %s", metadata.get("artifact_id"))
        # --- end final score ---


        # After running IOC and YARA (which update JSON/DB), refresh analysis from DB or file
        try:
            db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
            if db_artifact and db_artifact.analysis:
                try:
                    metadata["analysis"] = json.loads(db_artifact.analysis)
                except Exception:
                    metadata["analysis"] = db_artifact.analysis
            else:
                # fallback: read artifact metadata JSON on disk
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        file_meta = json.load(f)
                    metadata["analysis"] = file_meta.get("analysis")
                else:
                    metadata["analysis"] = None
        except Exception:
            # if anything goes wrong reading DB, try reading file and otherwise leave null
            try:
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        file_meta = json.load(f)
                    metadata["analysis"] = file_meta.get("analysis")
                else:
                    metadata["analysis"] = None
            except Exception:
                metadata["analysis"] = None

    except Exception:
        logger.exception("Hashing or update failed for %s", metadata.get("artifact_id"))

    manifest_count = len(manifest.get("artifacts", [])) if isinstance(manifest, dict) else 0

    # --- PUBLISH: append a timeline event for this uploaded artifact (non-blocking) ---
    try:
        ev = {
            "artifact_id": metadata.get("artifact_id"),
            "original_filename": metadata.get("original_filename"),
            "saved_filename": metadata.get("saved_filename"),
            "saved_path": metadata.get("saved_path"),
            "size_bytes": metadata.get("size_bytes"),
            "uploaded_by": metadata.get("uploaded_by"),
            "uploaded_at": metadata.get("uploaded_at"),
            "analysis": metadata.get("analysis")
        }

        # Build a small summary that the UI can render quickly
        summary = {
            "artifact_id": ev.get("artifact_id"),
            "filename": ev.get("original_filename"),
            "saved_filename": ev.get("saved_filename"),
            "saved_path": ev.get("saved_path"),
            "size_bytes": ev.get("size_bytes"),
            "uploaded_by": ev.get("uploaded_by"),
            # best-effort final_score if available
            "final_score": (ev.get("analysis") or {}).get("final_score") or (ev.get("analysis") or {}).get("suspicion_score")
        }

        try:
            utils_events.append_event(case_id, {
                "type": "artifact_uploaded",
                "artifact": ev,           # full manifest-ish object (for forensic detail)
                "summary": summary,       # small, UI-friendly summary
                "note": "uploaded via /upload"
            })
        except Exception:
            logger.exception("Failed to append upload event to events.json for %s/%s", case_id, metadata.get("artifact_id"))
    except Exception:
        logger.exception("Unexpected failure while building/publishing upload event for %s/%s", case_id, metadata.get("artifact_id"))


    # Return both metadata and DB id for convenience
    return jsonify({
        "status": "saved",
        "metadata": metadata,
        "db_artifact_id": getattr(artifact, "id", None) if 'artifact' in locals() else None,
        "manifest_summary_count": manifest_count
    })


@app.route("/api/upload_timeline", methods=["POST"])
def api_upload_timeline():
    return jsonify({
        "status": "gone",
        "message": "The /api/upload_timeline endpoint is deprecated. Please upload a single file or a case ZIP to /upload which now handles both single-file and ZIP ingestion and will generate timelines automatically."
    }), 410
    


@app.route("/dashboard")

def dashboard():
    """
    Dashboard: show case-level info (from DB) and artifacts list.
    Accepts optional ?case_id= parameter.
    """
    case_id = request.args.get("case_id", "case001")

    # load list of all cases for the case switcher (simple name list)
    try:
        case_rows = Case.query.order_by(Case.created_at.desc()).all()
        cases_list = [c.to_dict() for c in case_rows]  # each dict should at least include case_id
    except Exception:
        cases_list = []

    # Try to load case from DB; if missing fall back to manifest count
    case = Case.query.filter_by(case_id=case_id).first()
    if case:
        artifact_rows = Artifact.query.filter_by(case_id=case_id).order_by(Artifact.uploaded_at.desc()).all()
        artifacts = [r.to_dict() for r in artifact_rows]
        artifact_count = len(artifacts)
        case_info = case.to_dict()
    else:
        # fallback: existing manifest behavior (no DB case present)
        manifest = load_manifest(case_id)
        artifacts = manifest.get("artifacts", [])
        artifact_count = len(artifacts)
        case_info = {"case_id": case_id, "created_at": None, "artifact_count": artifact_count}

    # Render template with artifacts read from DB (or fallback)
    return render_template(
        "dashboard.html",
        case_id=case_id,
        artifact_count=artifact_count,
        suspicion_score=0,
        artifacts=artifacts,
        case_info=case_info,
        cases=cases_list,           # <-- new: pass all cases
    )

@app.route("/api/cases/<case_id>/events")
def case_events(case_id):
    events = get_events_for_case(case_id)  # must return list of dicts with serializable values
    return jsonify(events)

@app.route("/timeline")
def timeline():
    cases = list_cases()  # e.g. ["case001", "case002"]
    case_id = request.args.get("case_id", cases[0] if cases else "")
    return render_template("timeline.html", case_id=case_id, cases=cases)


@app.route("/report")
@login_required
def report():
    """
    Report preview: collect case & artifacts from DB (preferred) or manifest (fallback)
    and render templates/report.html for preview. Normalizes artifact records so the
    template always receives consistent fields (parses JSON strings, supplies defaults).
    """
    case_id = request.args.get("case_id", "case001")

    # Try DB first
    case = Case.query.filter_by(case_id=case_id).first()
    artifacts_raw = []
    case_info = {"case_id": case_id, "created_at": None, "artifact_count": 0}
    try:
        if case:
            artifacts_rows = Artifact.query.filter_by(case_id=case_id).order_by(Artifact.uploaded_at.desc()).all()
            # each row likely has a to_dict(); fallback to attribute read if not
            for r in artifacts_rows:
                try:
                    d = r.to_dict() if hasattr(r, "to_dict") else {
                        "artifact_id": getattr(r, "artifact_id", None),
                        "original_filename": getattr(r, "original_filename", None),
                        "saved_filename": getattr(r, "saved_filename", None),
                        "saved_path": getattr(r, "saved_path", None),
                        "uploaded_by": getattr(r, "uploaded_by", None),
                        "uploaded_at": getattr(r, "uploaded_at").isoformat() + "Z" if getattr(r, "uploaded_at", None) else None,
                        "size_bytes": getattr(r, "size_bytes", None),
                        "analysis": getattr(r, "analysis", None)
                    }
                except Exception:
                    # defensive fallback - build minimal dict
                    d = {
                        "artifact_id": getattr(r, "artifact_id", None),
                        "original_filename": getattr(r, "original_filename", None),
                        "saved_filename": getattr(r, "saved_filename", None),
                        "saved_path": getattr(r, "saved_path", None),
                        "uploaded_by": getattr(r, "uploaded_by", None),
                        "uploaded_at": getattr(r, "uploaded_at").isoformat() + "Z" if getattr(r, "uploaded_at", None) else None,
                        "size_bytes": getattr(r, "size_bytes", None),
                        "analysis": getattr(r, "analysis", None)
                    }
                artifacts_raw.append(d)
            case_info = case.to_dict() if hasattr(case, "to_dict") else {"case_id": case_id, "created_at": None, "artifact_count": len(artifacts_raw)}
        else:
            # fallback to manifest JSON
            manifest = load_manifest(case_id)
            artifacts_raw = manifest.get("artifacts", []) or []
            case_info = {"case_id": case_id, "created_at": manifest.get("created_at"), "artifact_count": len(artifacts_raw)}
    except Exception:
        # On any unexpected error, fallback to manifest and continue
        logger.exception("Error loading artifacts for report; falling back to manifest for case %s", case_id)
        manifest = load_manifest(case_id)
        artifacts_raw = manifest.get("artifacts", []) or []
        case_info = {"case_id": case_id, "created_at": manifest.get("created_at"), "artifact_count": len(artifacts_raw)}

    # Normalize artifacts into a predictable shape for the template
    artifacts = []
    for a in artifacts_raw:
        try:
            # a may be a DB-to_dict (dict), or manifest dict; analysis may be a JSON-string or dict
            art = dict(a) if isinstance(a, dict) else {}

            # ensure keys exist
            artifact_id = art.get("artifact_id") or art.get("id") or art.get("saved_filename") or "unknown"
            original_filename = art.get("original_filename") or art.get("original_name") or art.get("saved_filename") or "unknown"
            saved_filename = art.get("saved_filename") or original_filename
            saved_path = art.get("saved_path") or art.get("path") or None
            uploaded_by = art.get("uploaded_by") or art.get("uploader") or None
            uploaded_at = art.get("uploaded_at") or art.get("uploadedAt") or None
            size_bytes = art.get("size_bytes") if art.get("size_bytes") is not None else art.get("size") or art.get("size_bytes") or None

            # analysis may be JSON string from DB; parse if necessary
            analysis = art.get("analysis")
            if isinstance(analysis, str):
                try:
                    analysis = json.loads(analysis)
                except Exception:
                    # keep raw string if it cannot be parsed
                    analysis = {"raw": analysis}
            if analysis is None:
                analysis = art.get("heuristics") or art.get("analysis") or {}

            # ensure final_score is available under a known key for template
            final_score = None
            if isinstance(analysis, dict):
                final_score = analysis.get("final_score") or analysis.get("suspicion_score") or analysis.get("finalScore")

            artifacts.append({
                "artifact_id": artifact_id,
                "original_filename": original_filename,
                "saved_filename": saved_filename,
                "saved_path": saved_path,
                "uploaded_by": uploaded_by,
                "uploaded_at": uploaded_at,
                "size_bytes": size_bytes,
                "analysis": analysis,
                "final_score": final_score
            })
        except Exception:
            logger.exception("Failed to normalize artifact record for report: %r", a)
            # push a minimal fallback object so template stays stable
            artifacts.append({
                "artifact_id": getattr(a, "artifact_id", "unknown") if hasattr(a, "artifact_id") else "unknown",
                "original_filename": "unknown",
                "saved_filename": None,
                "saved_path": None,
                "uploaded_by": None,
                "uploaded_at": None,
                "size_bytes": None,
                "analysis": {},
                "final_score": None
            })

        # --- additional context needed by report.html (PDF/ZIP buttons, file presence) ---
    # data/<case_id> files used by timeline/report generation
    processes_path = os.path.join("data", case_id, "processes.csv")
    events_path = os.path.join("data", case_id, "events.json")
    processes_exists = os.path.exists(processes_path)
    events_exists = os.path.exists(events_path)

    # human-friendly generated timestamp (iso string)
    try:
        generated_at = iso_time_now()
    except Exception:
        generated_at = datetime.utcnow().isoformat() + "Z"

    # Try to build proper URLs for PDF / ZIP. If the reporting blueprint isn't present,
    # fall back to '#' so the template won't break (you can change the names to match your blueprint).
    try:
        # common case: reporting blueprint registered as 'reporting' with endpoints report_pdf, report_bundle
        pdf_url = url_for("reporting.report_pdf", case_id=case_id)
        bundle_url = url_for("reporting.report_bundle", case_id=case_id)
    except Exception:
        # fallback: try other likely names, then final fallback '#'
        try:
            pdf_url = url_for("report_pdf", case_id=case_id)
        except Exception:
            pdf_url = "#"
        try:
            bundle_url = url_for("report_bundle", case_id=case_id)
        except Exception:
            bundle_url = "#"

    # Render template with the extra context the template expects
    return render_template(
        "report.html",
        case_id=case_id,
        case_info=case_info,
        artifacts=artifacts,
        generated_at=generated_at,
        processes_path=processes_path,
        events_path=events_path,
        processes_exists=processes_exists,
        events_exists=events_exists,
        pdf_url=pdf_url,
        bundle_url=bundle_url,
    )




# ---------- render & serve PDF on-demand (regenerates from template) ----------
# Paste this block right after your existing `report()` view in app.py

from flask import make_response
from jinja2 import TemplateError

def _render_report_html(case_id):
    """
    Helper: reuse the same logic you use in /report to produce the template context
    and render the HTML string for the PDF. This mirrors your report() function's
    normalization so the PDF matches the page.
    """
    case_id_local = case_id

    # Same manifest/db logic used in your report() view
    case = Case.query.filter_by(case_id=case_id_local).first()
    artifacts_raw = []
    case_info = {"case_id": case_id_local, "created_at": None, "artifact_count": 0}
    try:
        if case:
            rows = Artifact.query.filter_by(case_id=case_id_local).order_by(Artifact.uploaded_at.desc()).all()
            for r in rows:
                try:
                    d = r.to_dict() if hasattr(r, "to_dict") else {
                        "artifact_id": getattr(r, "artifact_id", None),
                        "original_filename": getattr(r, "original_filename", None),
                        "saved_filename": getattr(r, "saved_filename", None),
                        "saved_path": getattr(r, "saved_path", None),
                        "uploaded_by": getattr(r, "uploaded_by", None),
                        "uploaded_at": getattr(r, "uploaded_at").isoformat() + "Z" if getattr(r, "uploaded_at", None) else None,
                        "size_bytes": getattr(r, "size_bytes", None),
                        "analysis": getattr(r, "analysis", None)
                    }
                except Exception:
                    d = {
                        "artifact_id": getattr(r, "artifact_id", None),
                        "original_filename": getattr(r, "original_filename", None),
                        "saved_filename": getattr(r, "saved_filename", None),
                        "saved_path": getattr(r, "saved_path", None),
                        "uploaded_by": getattr(r, "uploaded_by", None),
                        "uploaded_at": getattr(r, "uploaded_at").isoformat() + "Z" if getattr(r, "uploaded_at", None) else None,
                        "size_bytes": getattr(r, "size_bytes", None),
                        "analysis": getattr(r, "analysis", None)
                    }
                artifacts_raw.append(d)
            case_info = case.to_dict() if hasattr(case, "to_dict") else {"case_id": case_id_local, "created_at": None, "artifact_count": len(artifacts_raw)}
        else:
            manifest = load_manifest(case_id_local)
            artifacts_raw = manifest.get("artifacts", []) or []
            case_info = {"case_id": case_id_local, "created_at": manifest.get("created_at"), "artifact_count": len(artifacts_raw)}
    except Exception:
        manifest = load_manifest(case_id_local)
        artifacts_raw = manifest.get("artifacts", []) or []
        case_info = {"case_id": case_id_local, "created_at": manifest.get("created_at"), "artifact_count": len(artifacts_raw)}

    # Normalize artifacts (same normalization as report())
    artifacts = []
    for a in artifacts_raw:
        try:
            art = dict(a) if isinstance(a, dict) else {}
            artifact_id = art.get("artifact_id") or art.get("id") or art.get("saved_filename") or "unknown"
            original_filename = art.get("original_filename") or art.get("original_name") or art.get("saved_filename") or "unknown"
            saved_filename = art.get("saved_filename") or original_filename
            saved_path = art.get("saved_path") or art.get("path") or None
            uploaded_by = art.get("uploaded_by") or art.get("uploader") or None
            uploaded_at = art.get("uploaded_at") or art.get("uploadedAt") or None
            size_bytes = art.get("size_bytes") if art.get("size_bytes") is not None else art.get("size") or art.get("size_bytes") or None

            analysis = art.get("analysis")
            if isinstance(analysis, str):
                try:
                    analysis = json.loads(analysis)
                except Exception:
                    analysis = {"raw": analysis}
            if analysis is None:
                analysis = art.get("heuristics") or art.get("analysis") or {}

            final_score = None
            if isinstance(analysis, dict):
                final_score = analysis.get("final_score") or analysis.get("suspicion_score") or analysis.get("finalScore")

            artifacts.append({
                "artifact_id": artifact_id,
                "original_filename": original_filename,
                "saved_filename": saved_filename,
                "saved_path": saved_path,
                "uploaded_by": uploaded_by,
                "uploaded_at": uploaded_at,
                "size_bytes": size_bytes,
                "analysis": analysis,
                "final_score": final_score,
                # for template compatibility
                "meta": art,
                "meta_name": artifact_id
            })
        except Exception:
            artifacts.append({
                "artifact_id": getattr(a, "artifact_id", "unknown") if hasattr(a, "artifact_id") else "unknown",
                "original_filename": "unknown",
                "saved_filename": None,
                "saved_path": None,
                "uploaded_by": None,
                "uploaded_at": None,
                "size_bytes": None,
                "analysis": {},
                "final_score": None,
                "meta": a,
                "meta_name": "unknown"
            })

    processes_path = os.path.join("data", case_id_local, "processes.csv")
    events_path = os.path.join("data", case_id_local, "events.json")
    processes_exists = os.path.exists(processes_path)
    events_exists = os.path.exists(events_path)

    try:
        generated_at = iso_time_now()
    except Exception:
        generated_at = datetime.utcnow().isoformat() + "Z"

    # Render the template to HTML string
    try:
        html = render_template(
            "report.html",
            case_id=case_id_local,
            case_info=case_info,
            artifacts=artifacts,
            generated_at=generated_at,
            processes_path=processes_path,
            events_path=events_path,
            processes_exists=processes_exists,
            events_exists=events_exists,
            pdf_url="#",    # when generating PDF we don't need these links
            bundle_url="#"
        )
        return html
    except TemplateError:
        logger.exception("Failed to render report template for PDF generation")
        raise

@app.route("/report/bundle/<case_id>")
@login_required
def report_bundle_redirect(case_id):
    """
    Temporary compatibility redirect: forward legacy /report/bundle/<case_id>
    to the new blueprint-based route that generates/serves the zip.
    """
    # sanitize a bit
    try:
        safe = safe_case_id(case_id)
    except Exception:
        safe = None
    if not safe:
        return jsonify({"error": "invalid case id"}), 400

    # redirect to blueprint route (permanent if you want)
    return redirect(url_for("reporting.report_bundle", case_id=safe), code=302)


@app.route("/report/pdf/<case_id>")
@login_required
def report_pdf(case_id):
    """
    Render the report template and attempt to convert to PDF on-the-fly.
    Tries WeasyPrint first, then pdfkit/wkhtmltopdf. Falls back to serving
    an existing on-disk PDF if conversion fails.
    """
    html = _render_report_html(case_id)

    # 2) Try pdfkit (wkhtmltopdf)
    try:
        import pdfkit
        # If wkhtmltopdf is not in PATH, optionally user can set PDFKIT_WKHTMLTOPDF env var.
        wkhtml_exe = os.environ.get("PDFKIT_WKHTMLTOPDF")  # e.g. "C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe"
        if wkhtml_exe:
            config = pdfkit.configuration(wkhtmltopdf=wkhtml_exe)
            pdf_bytes = pdfkit.from_string(html, False, options={"enable-local-file-access": None}, configuration=config)
        else:
            pdf_bytes = pdfkit.from_string(html, False, options={"enable-local-file-access": None})
        resp = make_response(pdf_bytes)
        resp.headers.set("Content-Type", "application/pdf")
        resp.headers.set("Content-Disposition", f"attachment; filename={case_id}_report.pdf")
        logger.info("PDF generated with pdfkit/wkhtmltopdf for %s", case_id)
        return resp
    except Exception as e:
        logger.exception("pdfkit/wkhtmltopdf generation failed or not available: %s", e)

    # 3) Fallback: serve pre-generated file on disk if exists (check many likely locations)
    # Build candidate list robustly (handles Windows/Unix path separators)
    candidates = []
    # data/<case_id>/report.pdf
    candidates.append(os.path.normpath(os.path.join(DATA_DIR, case_id, "report.pdf")))
    # data/<case_id>_report.pdf
    candidates.append(os.path.normpath(os.path.join(DATA_DIR, f"{case_id}_report.pdf")))
    # PROJECT_ROOT/<case_id>_report.pdf
    candidates.append(os.path.normpath(os.path.join(PROJECT_ROOT, f"{case_id}_report.pdf")))
    # /mnt/data/<case_id>_report.pdf (useful in cloud/dev containers)
    try:
        candidates.append(os.path.normpath(os.path.join("/mnt/data", f"{case_id}_report.pdf")))
    except Exception:
        pass
    # also check /tmp variants (some systems)
    try:
        candidates.append(os.path.normpath(os.path.join("/tmp", f"{case_id}_report.pdf")))
    except Exception:
        pass

    checked = []
    for p in candidates:
        checked.append(p)
        if p and os.path.exists(p):
            logger.info("Serving existing on-disk PDF for %s: %s", case_id, p)
            # Flask send_file on some versions requires download_name kw only on newer Flask; using send_file fallback
            return send_file(p, as_attachment=True, download_name=os.path.basename(p) if hasattr(send_file, '__call__') else os.path.basename(p))

    # nothing found — return JSON error (helpful for debugging)
    logger.error("PDF generation failed and no on-disk report found (checked: %s)", checked)
    return jsonify({"error": "PDF generation failed and no on-disk report found", "checked": checked}), 500


@app.route("/report/bundle/<case_id>")
@login_required
def report_bundle(case_id):
    """
    Serve an existing case zip if present, otherwise build a zip containing
    report.pdf and manifest.json (and small helpful files) on demand.
    """
    import glob, tempfile, shutil
    try:
        # 1) Look for an existing zip (many likely names / locations)
        candidates = []
        candidates += glob.glob(os.path.join(DATA_DIR, case_id, f"*{case_id}*.zip"))
        candidates.append(os.path.join(DATA_DIR, case_id, f"{case_id}_package.zip"))
        candidates.append(os.path.join(DATA_DIR, case_id, f"{case_id}_report.zip"))
        candidates.append(os.path.join(DATA_DIR, f"{case_id}_package.zip"))
        candidates.append(os.path.join(PROJECT_ROOT, f"{case_id}_package.zip"))
        candidates.append(os.path.join(PROJECT_ROOT, f"{case_id}_report.zip"))
        candidates.append(os.path.join("/mnt/data", f"{case_id}_package.zip"))
        candidates.append(os.path.join("/tmp", f"{case_id}_package.zip"))

        # flatten & dedupe
        seen = set(); cand_list = []
        for c in candidates:
            if isinstance(c, (list, tuple)):
                for x in c:
                    if x and x not in seen:
                        seen.add(x); cand_list.append(x)
            else:
                if c and c not in seen:
                    seen.add(c); cand_list.append(c)

        for p in cand_list:
            try:
                if p and os.path.exists(p) and os.path.getsize(p) > 0:
                    current_app.logger.info("Found existing zip for %s -> %s", case_id, p)
                    try:
                        return send_file(p, as_attachment=True, download_name=os.path.basename(p))
                    except TypeError:
                        return send_file(p, as_attachment=True, attachment_filename=os.path.basename(p))
            except Exception:
                continue

        # 2) No pre-built zip found -> assemble from PDF + manifest
        pdf_candidates = [
            os.path.join(DATA_DIR, case_id, "report.pdf"),
            os.path.join(DATA_DIR, f"{case_id}_report.pdf"),
            os.path.join(PROJECT_ROOT, f"{case_id}_report.pdf"),
            os.path.join("/mnt/data", f"{case_id}_report.pdf"),
            os.path.join("/tmp", f"{case_id}_report.pdf"),
        ]
        pdf_path = next((p for p in pdf_candidates if p and os.path.exists(p) and os.path.getsize(p) > 0), None)
        manifest_path = os.path.join(DATA_DIR, case_id, "manifest.json")
        if not (manifest_path and os.path.exists(manifest_path) and os.path.getsize(manifest_path) > 0):
            manifest_path = None

        if not pdf_path and not manifest_path:
            current_app.logger.warning("report_bundle: no pdf or manifest or zip found for %s", case_id)
            return jsonify({"error": "no report or manifest found"}), 404

        with tempfile.TemporaryDirectory() as tmpd:
            pkg_dir = os.path.join(tmpd, "package_contents")
            os.makedirs(pkg_dir, exist_ok=True)
            if pdf_path:
                try: shutil.copy2(pdf_path, os.path.join(pkg_dir, os.path.basename(pdf_path)))
                except Exception: current_app.logger.exception("Failed to copy pdf into temp package for %s", case_id)
            if manifest_path:
                try: shutil.copy2(manifest_path, os.path.join(pkg_dir, os.path.basename(manifest_path)))
                except Exception: current_app.logger.exception("Failed to copy manifest into temp package for %s", case_id)

            # include small JSON/log files
            small_exts = ("*.log", "*.json", "*.txt")
            case_folder = os.path.join(DATA_DIR, case_id)
            if os.path.exists(case_folder):
                import glob
                for ext in small_exts:
                    for f in glob.glob(os.path.join(case_folder, ext)):
                        try:
                            if os.path.getsize(f) < 5 * 1024 * 1024:
                                shutil.copy2(f, os.path.join(pkg_dir, os.path.basename(f)))
                        except Exception:
                            continue

            zip_out = os.path.join(tmpd, f"{case_id}_package.zip")
            archive = shutil.make_archive(zip_out.replace(".zip", ""), 'zip', root_dir=pkg_dir)
            try:
                return send_file(archive, as_attachment=True, download_name=os.path.basename(archive))
            except TypeError:
                return send_file(archive, as_attachment=True, attachment_filename=os.path.basename(archive))

    except Exception as e:
        current_app.logger.exception("report_bundle error for %s: %s", case_id, e)
        return jsonify({"error": "failed to prepare bundle", "details": str(e)}), 500


@app.route("/heuristics", methods=["GET", "POST"])
def heuristics_upload():
    """
    Ad-hoc UI: upload a file (choose a case_id if desired) to run heuristics analysis.
    Renders templates/heuristics_upload.html (create this template — I provided earlier).
    """
    if request.method == "POST":
        # reuse your existing save_uploaded_file helper that accepts file + case_id
        file = request.files.get("file")
        case_id = request.form.get("case_id", "case001")
        uploader = request.form.get("uploader", "investigator")
        if not file:
            flash("No file provided", "danger")
            return redirect(request.url)
        try:
            metadata = save_uploaded_file(file, case_id=case_id, uploader=uploader, allowed_ext_set=ALLOWED_EXTENSIONS)
        except Exception as e:
            logger.exception("Upload failed in /heuristics")
            flash(f"Upload failed: {e}", "danger")
            return redirect(request.url)

        # Run heuristics
        try:
            heuristics_report = analyze_file(metadata["saved_path"])
            metadata["heuristics"] = heuristics_report
            # Persist heuristics into DB and artifact JSON (same approach as upload_file)
            try:
                db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
                existing = {}
                if db_artifact:
                    try:
                        if db_artifact.analysis:
                            existing = json.loads(db_artifact.analysis) if isinstance(db_artifact.analysis, str) else db_artifact.analysis
                    except Exception:
                        existing = {}
                    existing.setdefault("heuristics", heuristics_report)
                    db_artifact.analysis = json.dumps(existing)
                    db.session.add(db_artifact)
                    db.session.commit()
                    metadata["analysis"] = existing
                else:
                    metadata["analysis"] = {"heuristics": heuristics_report}
                # write artifact JSON file (robust merge + sign)
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                try:
                    on_disk_meta = mutils.load_signed_metadata_safe(meta_path)
                    on_disk_meta = mutils.normalize_metadata_dict(on_disk_meta)
                    on_disk_meta.setdefault("analysis", {})
                    on_disk_meta["analysis"].setdefault("heuristics", heuristics_report)

                    try:
                        mutils.write_signed_metadata(meta_path, on_disk_meta)
                    except Exception:
                        logger.exception("Failed to write & sign heuristics artifact metadata for %s; attempting atomic write", metadata.get("artifact_id"))
                        try:
                            mutils.atomic_write_json(meta_path, on_disk_meta)
                        except Exception:
                            logger.exception("Fallback atomic write failed for heuristics metadata %s", metadata.get("artifact_id"))
                except Exception:
                    logger.exception("Failed to write heuristics into artifact JSON on disk for %s", metadata.get("artifact_id"))

            except Exception:
                logger.exception("Failed to persist heuristics from /heuristics upload")
        except Exception:
            logger.exception("Heuristics analysis failed in /heuristics")
            flash("Heuristics analysis failed; see server logs", "warning")
            return redirect(request.url)

        # Render result page
        return render_template("heuristics_upload.html", report=metadata.get("heuristics"), metadata=metadata)

    # GET
    return render_template("heuristics_upload.html", report=None, metadata=None)


@app.route("/api/heuristics", methods=["POST"])
def heuristics_api():
    """
    Programmatic API: accept multipart form-data field 'file' and optional 'case_id' & 'uploader'.
    Returns the heuristics report JSON and persists it similarly to the upload flow.
    """
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "no file provided"}), 400
    case_id = request.form.get("case_id", "case001")
    uploader = request.form.get("uploader", "investigator")
    try:
        metadata = save_uploaded_file(file, case_id=case_id, uploader=uploader, allowed_ext_set=ALLOWED_EXTENSIONS)
    except ValueError as ve:
        logger.warning("Upload blocked in API: %s", ve)
        return jsonify({"error": str(ve)}), 400
    except Exception:
        logger.exception("Upload failed in API /api/heuristics")
        return jsonify({"error": "failed to save uploaded file"}), 500

    try:
        heuristics_report = analyze_file(metadata["saved_path"])
        metadata["heuristics"] = heuristics_report
    except Exception:
        logger.exception("Heuristics analysis failed in API")
        return jsonify({"error": "heuristics analysis failed"}), 500

    # Persist to DB + artifact JSON
    try:
        db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
        existing = {}
        if db_artifact:
            try:
                if db_artifact.analysis:
                    existing = json.loads(db_artifact.analysis) if isinstance(db_artifact.analysis, str) else db_artifact.analysis
            except Exception:
                existing = {}
            existing.setdefault("heuristics", heuristics_report)
            db_artifact.analysis = json.dumps(existing)
            db.session.add(db_artifact)
            db.session.commit()
            metadata["analysis"] = existing
        else:
            metadata["analysis"] = {"heuristics": heuristics_report}
        # write artifact JSON file
        meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
        on_disk_meta = {}
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    on_disk_meta = json.load(fh)
            except Exception:
                on_disk_meta = {}
        on_disk_meta.setdefault("analysis", {})
        on_disk_meta["analysis"].setdefault("heuristics", heuristics_report)
        try:
            mutils.write_signed_metadata(meta_path, on_disk_meta)
        except Exception:
            logger.exception("Failed to write & sign heuristics artifact metadata for %s; attempting atomic write", metadata.get("artifact_id"))
            try:
                tmp = meta_path + ".tmp"
                with open(tmp, "w", encoding='utf-8') as fh:
                    json.dump(on_disk_meta, fh, indent=2)
                os.replace(tmp, meta_path)
            except Exception:
                logger.exception("Fallback atomic write failed for heuristics metadata %s", metadata.get("artifact_id"))
    except Exception:
        logger.exception("Failed to persist heuristics in API for %s", metadata.get("artifact_id"))

    return jsonify({"status": "ok", "heuristics": heuristics_report, "metadata": metadata})




@app.route("/test-analysis")
def test_analysis():
    return "Test analysis route (no-op for upload demo)."


@app.route("/artifact/<case_id>/<artifact_filename>")
def download_artifact(case_id, artifact_filename):
    _, artifacts_dir = ensure_case_dirs(case_id)
    safe_path = os.path.join(artifacts_dir, artifact_filename)
    if not os.path.exists(safe_path):
        abort(404)
    return send_file(safe_path, as_attachment=True)


@app.route("/api/manifest/<case_id>")
def api_manifest(case_id):
    manifest = load_manifest(case_id)
    return jsonify(manifest)


# Optional: API endpoints to query DB records (for later frontend usage)
@app.route("/api/db/case/<case_id>")
def api_db_case(case_id):
    case = Case.query.filter_by(case_id=case_id).first()
    if not case:
        return jsonify({"error": "case not found"}), 404
    return jsonify(case.to_dict())


@app.route("/api/db/artifacts/<case_id>")
@api_login_required
def api_db_artifacts(case_id):
    rows = Artifact.query.filter_by(case_id=case_id).all()
    return jsonify([r.to_dict() for r in rows])

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({"error": "Uploaded file is too large"}), 413

@app.route("/api/ioc_check/<case_id>/<artifact_id>", methods=["GET", "POST"])
def api_ioc_check(case_id, artifact_id):
    """
    Trigger IOC matching for a single artifact and return the matches.
    """
    try:
        result = check_iocs_for_artifact(case_id, artifact_id)
        return jsonify({"status": "ok", "result": result})
    except FileNotFoundError as e:
        return jsonify({"status": "error", "error": str(e)}), 404
    except Exception as e:
        logger.exception("IOC check failed for %s/%s", case_id, artifact_id)
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/yara_check/<case_id>/<artifact_id>", methods=["GET", "POST"])
def api_yara_check(case_id, artifact_id):
    """
    Trigger YARA scan for a single artifact and return matches.
    """
    try:
        result = yara_scan_artifact(case_id, artifact_id)
        if result.get("error"):
            return jsonify({"status": "error", "error": result.get("error"), "result": result}), 500
        return jsonify({"status": "ok", "result": result})
    except Exception as e:
        logger.exception("YARA API check failed for %s/%s", case_id, artifact_id)
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/recompute_score/<case_id>/<artifact_id>", methods=["POST", "GET"])
def api_recompute_score(case_id, artifact_id):
    """
    Recompute IOC, YARA and Heuristics for a single artifact then compute & persist final score.
    - Runs: check_iocs_for_artifact, yara_scan_artifact, analyze_file (heuristics), compute_final_score
    - Persists results to: artifact JSON file (evidence/<case>/artifacts/<artifact_id>.json),
      case manifest, and DB Artifact.analysis
    Returns: JSON with final_score, breakdown and component details.
    """
    try:
        # 1) locate artifact JSON on disk
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
        if not os.path.exists(meta_path):
            return jsonify({"status": "error", "error": "artifact metadata not found", "path": meta_path}), 404

        # load artifact metadata
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except Exception as e:
            logger.exception("Failed to load artifact metadata for recompute %s/%s", case_id, artifact_id)
            return jsonify({"status": "error", "error": f"failed to load metadata: {e}"}), 500

        saved_path = meta.get("saved_path")
        # fallback: find file by prefix if saved_path missing
        if (not saved_path or not os.path.exists(saved_path)) and os.path.exists(artifacts_dir):
            for fn in os.listdir(artifacts_dir):
                if fn.startswith(artifact_id + "__"):
                    saved_path = os.path.join(artifacts_dir, fn)
                    break

        # 2) recompute SHA (if necessary) and ensure metadata sha present
        try:
            if saved_path and os.path.exists(saved_path):
                from modules.hashing import compute_sha256, update_artifact_hash
                sha = meta.get("sha256")
                if not sha:
                    sha, _ = compute_sha256(saved_path)
                    meta["sha256"] = sha
                    # ensure DB/manifest updated by calling update_artifact_hash helper
                    try:
                        update_artifact_hash(case_id, artifact_id, sha)
                    except Exception:
                        logger.debug("update_artifact_hash failed (ok) during recompute for %s", artifact_id)
        except Exception:
            logger.exception("failed to compute sha during recompute for %s/%s", case_id, artifact_id)

        # 3) re-run IOC
        ioc_matches = []
        try:
            ioc_res = check_iocs_for_artifact(case_id, artifact_id)
            ioc_matches = ioc_res.get("matches", []) if isinstance(ioc_res, dict) else []
            meta.setdefault("analysis", {}).setdefault("ioc_matches", ioc_matches)
        except FileNotFoundError:
            # artifact missing/inconsistent
            logger.warning("IOC recompute: artifact metadata not found for %s/%s", case_id, artifact_id)
        except Exception:
            logger.exception("IOC recompute failed for %s/%s", case_id, artifact_id)

        # 4) re-run YARA
        yara_matches = []
        try:
            yara_res = yara_scan_artifact(case_id, artifact_id)
            if isinstance(yara_res, dict):
                yara_matches = yara_res.get("matches", []) or []
                # also record yara_available flag if present
                if "yara_available" in yara_res:
                    meta.setdefault("analysis", {})["yara_available"] = yara_res.get("yara_available")
                meta.setdefault("analysis", {})["yara_matches"] = yara_matches
        except Exception:
            logger.exception("YARA recompute failed for %s/%s", case_id, artifact_id)

        # 5) re-run heuristics (optional but recommended to refresh heuristics results)
        heuristics_report = {}
        try:
            if saved_path and os.path.exists(saved_path):
                heuristics_report = analyze_file(saved_path)
                meta.setdefault("analysis", {})["heuristics"] = heuristics_report
        except Exception:
            logger.exception("Heuristics recompute failed for %s/%s", case_id, artifact_id)

        # 6) compute final score
        try:
            from modules.scoring import compute_final_score
            final = compute_final_score(meta.get("analysis") or meta)
            # attach final results to meta.analysis
            meta.setdefault("analysis", {})
            meta["analysis"]["final_score"] = final.get("final_score")
            meta["analysis"]["final_breakdown"] = final.get("breakdown")
            meta["analysis"]["final_reasons"] = final.get("reasons")
        except Exception:
            logger.exception("Final scoring failed for %s/%s", case_id, artifact_id)
            return jsonify({"status": "error", "error": "scoring failed"}), 500

        # 7) persist changes: artifact JSON (signed preferred, atomic fallback), merge safely
        try:
            existing = mutils.load_signed_metadata_safe(meta_path)
            existing = mutils.normalize_metadata_dict(existing)            # overlay new meta (avoid copying any _meta)
            existing.pop("_meta", None)
            # merge analysis/top-level keys from meta into existing
            for k, v in (meta or {}).items():
                if k == "_meta":
                    continue
                if k == "analysis" and isinstance(v, dict):
                    existing.setdefault("analysis", {})
                    existing["analysis"].update(v)
                else:
                    existing[k] = v

            try:
                mutils.write_signed_metadata(meta_path, existing)
            except Exception:
                logger.exception("Failed to write & sign updated artifact metadata for %s/%s; attempting atomic write", case_id, artifact_id)
                try:
                    mutils.atomic_write_json(meta_path, existing)
                except Exception:
                    logger.exception("Fallback atomic write failed for recompute metadata %s/%s", case_id, artifact_id)
        except Exception:
            logger.exception("Failed to persist updated artifact metadata for %s/%s", case_id, artifact_id)

        # 8) persist to DB (Artifact.analysis)
        try:
            art = Artifact.query.filter_by(artifact_id=artifact_id).first()
            if art:
                existing = {}
                if art.analysis:
                    try:
                        existing = json.loads(art.analysis)
                    except Exception:
                        existing = {}
                # merge
                existing.update(meta.get("analysis", {}))
                art.analysis = json.dumps(existing)
                db.session.add(art)
                db.session.commit()
        except Exception:
            logger.exception("Failed to update DB analysis for %s/%s", case_id, artifact_id)

        # 9) update manifest entry
        try:
            manifest = load_manifest(case_id)
            changed = False
            for entry in manifest.get("artifacts", []):
                if entry.get("artifact_id") == artifact_id:
                    entry["analysis"] = meta.get("analysis")
                    entry["suspicion_score"] = meta.get("analysis", {}).get("final_score")
                    changed = True
                    break
            if changed:
                save_manifest(case_id, manifest)
        except Exception:
            logger.exception("Failed to update manifest for %s/%s", case_id, artifact_id)

        # publish recompute event to timeline (non-blocking)
        try:
            utils_events.append_event(case_id, {
                "type": "recompute_score",
                "artifact_id": artifact_id,
                "final_score": meta.get("analysis", {}).get("final_score"),
                "details": {"ioc_matches_count": len(ioc_matches), "yara_matches_count": len(yara_matches)}
            })
        except Exception:
            logger.exception("Failed to append recompute event for %s/%s", case_id, artifact_id)


        # 10) return structured result
        return jsonify({
            "status": "ok",
            "artifact_id": artifact_id,
            "case_id": case_id,
            "final_score": meta.get("analysis", {}).get("final_score"),
            "final_breakdown": meta.get("analysis", {}).get("final_breakdown"),
            "final_reasons": meta.get("analysis", {}).get("final_reasons"),
            "ioc_matches": ioc_matches,
            "yara_matches": yara_matches,
            "heuristics": heuristics_report
        })
    except Exception:
        logger.exception("Unexpected error during recompute for %s/%s", case_id, artifact_id)
        return jsonify({"status": "error", "error": "unexpected server error"}), 500

@app.route("/api/case/<case_id>/counts")
def api_case_counts(case_id):
    """
    Return counts for artifacts (DB) and timeline (data/<case_id>/events.json).
    Useful for the dashboard badge showing divergence.
    """
    try:
        artifact_count = Artifact.query.filter_by(case_id=case_id).count()
    except Exception:
        artifact_count = 0

    timeline_count = 0
    try:
        events_path = os.path.join("data", case_id, "events.json")
        if os.path.exists(events_path):
            with open(events_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for ev in data.get("timeline_preview", []):
                details = ev.get("details", {})
                if details.get("case_id") == case_id:
                    timeline_count += len(details.get("artifacts", []))
    except Exception:
        timeline_count = 0

    return jsonify({"artifact_count": artifact_count, "timeline_count": timeline_count})


@app.route("/api/coc/add", methods=["POST"])
def api_coc_add():
    """
    Add a Chain-of-Custody entry.
    Body JSON: case_id, artifact_id, actor, action, from, to, reason, location, details (optional dict)
    """
    body = request.get_json(force=True) or {}
    case_id = body.get("case_id")
    artifact_id = body.get("artifact_id")
    actor = body.get("actor", "unknown")
    action = body.get("action", "access")
    from_entity = body.get("from")
    to_entity = body.get("to")
    reason = body.get("reason")
    location = body.get("location")
    details = body.get("details")

    if not case_id or not artifact_id:
        return jsonify({"error": "case_id and artifact_id required"}), 400

    try:
        # Create DB row
        coc = ChainOfCustody(
            case_id=case_id,
            artifact_id=artifact_id,
            actor=actor,
            action=action,
            from_entity=from_entity,
            to_entity=to_entity,
            reason=reason,
            location=location,
            details=json.dumps(details) if details else None
        )
        db.session.add(coc)
        db.session.commit()

        # Build payload to sign/store on-disk
        payload = {
            "ts": coc.ts.isoformat() + "Z",
            "case_id": case_id,
            "artifact_id": artifact_id,
            "actor": actor,
            "action": action,
            "from": from_entity,
            "to": to_entity,
            "reason": reason,
            "location": location,
            "details": details
        }

        # compute signature (HMAC) and persist into DB record
        signature = hmac_for_obj(payload)
        coc.signature = signature
        db.session.add(coc)
        db.session.commit()

        # Append to artifact metadata on disk (safely), and re-sign artifact JSON
        try:
            _, artifacts_dir = ensure_case_dirs(case_id)
            meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                # ensure analysis.coc is a list
                meta.setdefault("analysis", {}).setdefault("coc", [])
                # Python 3.9+: merge, but to be safe create a copy for older versions
                entry = dict(payload)
                entry["signature"] = signature
                meta["analysis"]["coc"].append(entry)
                # write & sign artifact metadata (write_signed_metadata provided in modules.utils)
                try:
                    write_signed_metadata(meta_path, meta)
                except Exception:
                    # fallback: atomic_write_json if write_signed_metadata unavailable
                    logger.exception("Failed to write_signed_metadata for %s/%s; attempting atomic write", case_id, artifact_id)
                    try:
                        atomic_write_json(meta_path, meta)
                    except Exception:
                        logger.exception("Failed fallback atomic write for CoC append %s/%s", case_id, artifact_id)
        except Exception:
            logger.exception("Failed to append CoC entry to artifact JSON for %s/%s", case_id, artifact_id)

        # Audit the CoC add action
        try:
            record_audit(db, case_id, artifact_id, actor, "coc_add", {"action": action, "signature": signature})
        except Exception:
            logger.exception("Failed to record audit for CoC add %s/%s", case_id, artifact_id)

        # Append CoC timeline event (non-blocking)
        try:
            utils_events.append_event(case_id, {
                "type": "coc_add",
                "actor": actor,
                "action": action,
                "artifact_id": artifact_id,
                "signature": signature
            })
        except Exception:
            logger.exception("Failed to append CoC timeline event for %s/%s", case_id, artifact_id)

        return jsonify({"status": "ok", "id": coc.id, "signature": signature}), 201

    except Exception as e:
        db.session.rollback()
        logger.exception("Failed to create CoC entry for %s/%s", case_id, artifact_id)
        return jsonify({"error": str(e)}), 500


@app.route("/api/coc/<case_id>/<artifact_id>", methods=["GET"])
def api_coc_get(case_id, artifact_id):
    """
    Resilient CoC GET: try ORM first; if that returns nothing or fails, fallback to direct sqlite query.
    """
    try:
        # lazy import (safe)
        from modules.models import ChainOfCustody
        logger.info("api_coc_get ORM attempt for %s / %s", case_id, artifact_id)
        try:
            rows = ChainOfCustody.query.filter_by(case_id=case_id, artifact_id=artifact_id).order_by(ChainOfCustody.ts.asc()).all()
            out = [r.to_dict() for r in rows]
            logger.info("ORM returned %d rows", len(out))
            if out:
                return jsonify(out)
            # else fall through to sqlite fallback
        except Exception:
            logger.exception("ORM query failed; falling back to sqlite")
    except Exception:
        logger.exception("Importing ChainOfCustody failed; falling back to sqlite")

    # ---------- sqlite fallback ----------
    try:
        import sqlite3, os, json
        db_path = os.path.join(PROJECT_ROOT, "data", "triage.db")
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT id, ts, case_id, artifact_id, actor, action, details, signature FROM chain_of_custody WHERE case_id=? AND artifact_id=? ORDER BY ts ASC", (case_id, artifact_id))
        rows = []
        for id_, ts, caseid, aid, actor, action, details, signature in cur.fetchall():
            try:
                det = json.loads(details) if details else None
            except Exception:
                det = details
            rows.append({
                "id": id_,
                "ts": ts,
                "case_id": caseid,
                "artifact_id": aid,
                "actor": actor,
                "action": action,
                "details": det,
                "signature": signature
            })
        con.close()
        logger.info("sqlite fallback returned %d rows", len(rows))
        return jsonify(rows)
    except Exception:
        logger.exception("sqlite fallback failed for CoC get %s/%s", case_id, artifact_id)
        return jsonify({"error": "failed to fetch"}), 500


@app.route("/api/coc/verify/<case_id>/<artifact_id>", methods=["GET"])
def api_coc_verify(case_id, artifact_id):
    try:
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
        if not os.path.exists(meta_path):
            return jsonify({"status": "error", "error": "metadata missing"}), 404

        ok, details = verify_signed_metadata(meta_path)
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)

        # figure out on-disk reference SHA
        on_disk_sha = None
        if meta.get("analysis", {}):
            on_disk_sha = meta.get("analysis", {}).get("latest_sha256") or meta.get("analysis", {}).get("sha256")
        if not on_disk_sha:
            on_disk_sha = meta.get("sha256")

        saved_path = meta.get("saved_path")
        computed_sha = None
        if saved_path and os.path.exists(saved_path):
            try:
                computed_sha, _ = compute_sha256(saved_path)
            except Exception:
                logger.exception("Failed to compute sha for %s/%s", case_id, artifact_id)

        result = {
            "metadata_hmac_ok": ok,
            "metadata_hmac_details": details,
            "on_disk_sha256": on_disk_sha,
            "computed_sha256": computed_sha
        }

        # Publish verification outcome to timeline (non-blocking)
        try:
            utils_events.append_event(case_id, {
                "type": "coc_verify",
                "artifact_id": artifact_id,
                "metadata_hmac_ok": ok,
                "on_disk_sha256": on_disk_sha,
                "computed_sha256": computed_sha
            })
        except Exception:
            logger.exception("Failed to append CoC verify event for %s/%s", case_id, artifact_id)


        # Audit results
        if not ok:
            record_audit(db, case_id, artifact_id, "system:verifier", "metadata_hmac_mismatch", details)
        if on_disk_sha and computed_sha and on_disk_sha != computed_sha:
            record_audit(db, case_id, artifact_id, "system:verifier", "hash_mismatch", {"expected": on_disk_sha, "observed": computed_sha})
        elif computed_sha is not None:
            record_audit(db, case_id, artifact_id, "system:verifier", "hash_ok", {"sha256": computed_sha})

        # --- NEW: add Chain-of-Custody entry reflecting verification result ---
        try:
            from modules.utils import add_coc_entry
            coc_action = "metadata_verified" if ok else "metadata_tampered"
            coc_details = details if isinstance(details, dict) else {"details": details}
            add_coc_entry(db, case_id, artifact_id, actor="system:verifier", action=coc_action, location="server", details=coc_details)
            
        except Exception:
            logger.exception("Failed to create CoC entry after verification for %s/%s", case_id, artifact_id)

        return jsonify(result)

    except Exception:
        logger.exception("Verification endpoint failed for %s/%s", case_id, artifact_id)
        return jsonify({"error": "verification failed"}), 500

# add near other route handlers in app.py (replace any existing view_case_coc)
from flask import render_template
from modules.models import ChainOfCustody  # already imported earlier in your file
import sqlite3, json


from datetime import datetime, timezone, timedelta
@app.route("/coc/case/<case_id>")
def view_case_coc(case_id):
    """
    Render case-level Chain-of-Custody / audit entries aggregated for the case.
    Shows timestamps converted to IST and includes artifact filename (if available).
    """
    try:
        entries = []

        # Primary: use ORM if available
        try:
            rows = ChainOfCustody.query.filter_by(case_id=case_id).order_by(ChainOfCustody.ts.asc()).all()
            for r in rows:
                try:
                    # ts -> IST 24h format "YYYY-MM-DD HH:MM:SS"
                    raw_ts = getattr(r, "ts", None)
                    ist_ts = None
                    if raw_ts:
                        try:
                            if isinstance(raw_ts, str):
                                # try parse ISO string (handle trailing Z)
                                s = raw_ts
                                if s.endswith("Z"):
                                    s = s[:-1]
                                raw_dt = datetime.fromisoformat(s)
                                # assume UTC if naive
                                if raw_dt.tzinfo is None:
                                    raw_dt = raw_dt.replace(tzinfo=timezone.utc)
                            elif isinstance(raw_ts, datetime):
                                raw_dt = raw_ts if raw_ts.tzinfo is not None else raw_ts.replace(tzinfo=timezone.utc)
                            else:
                                raw_dt = None

                            if raw_dt is not None:
                                ist_tz = timezone(timedelta(hours=5, minutes=30))
                                ist_dt = raw_dt.astimezone(ist_tz)
                                ist_ts = ist_dt.strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            ist_ts = getattr(r, "ts", None)
                    else:
                        ist_ts = None
                except Exception:
                    ist_ts = getattr(r, "ts", None)

                # Try to obtain filename from Artifact table (best-effort)
                filename = None
                try:
                    art = Artifact.query.filter_by(artifact_id=r.artifact_id, case_id=case_id).first()
                    if art:
                        filename = getattr(art, "original_filename", None) or getattr(art, "saved_filename", None)
                except Exception:
                    filename = None

                # parse details JSON if present
                details_val = None
                try:
                    details_raw = getattr(r, "details", None)
                    if details_raw:
                        if isinstance(details_raw, str):
                            try:
                                details_val = json.loads(details_raw)
                            except Exception:
                                details_val = details_raw
                        else:
                            details_val = details_raw
                except Exception:
                    details_val = None

                entries.append({
                    "id": getattr(r, "id", None),
                    "ts": ist_ts,
                    "case_id": getattr(r, "case_id", None),
                    "artifact_id": getattr(r, "artifact_id", None),
                    "filename": filename,
                    "actor": getattr(r, "actor", None),
                    "action": getattr(r, "action", None),
                    "details": details_val,
                    "signature": getattr(r, "signature", None)
                })
        except Exception:
            # ORM failed -> sqlite fallback with LEFT JOIN to artifacts for filename
            entries = []
            db_path = os.path.join(PROJECT_ROOT, "data", "triage.db")
            try:
                con = sqlite3.connect(db_path)
                cur = con.cursor()
                # left join artifacts to fetch a.original_filename when available
                cur.execute("""
                    SELECT c.id, c.ts, c.case_id, c.artifact_id,
                           a.original_filename, a.saved_filename,
                           c.actor, c.action, c.details, c.signature
                    FROM chain_of_custody c
                    LEFT JOIN artifacts a ON a.artifact_id = c.artifact_id AND a.case_id = c.case_id
                    WHERE c.case_id = ?
                    ORDER BY c.ts ASC
                """, (case_id,))
                rows = cur.fetchall()
                for row in rows:
                    # row: id, ts, case_id, artifact_id, original_filename, saved_filename, actor, action, details, signature
                    try:
                        id_, ts_raw, caseid, aid, orig_fn, saved_fn, actor, action, details_raw, signature = row
                    except ValueError:
                        # fallback for different schema
                        id_, ts_raw, caseid, aid, actor, action, details_raw = row
                        orig_fn = saved_fn = signature = None

                    # normalize timestamp to IST string
                    ist_ts = None
                    try:
                        if ts_raw:
                            if isinstance(ts_raw, bytes):
                                ts_raw = ts_raw.decode('utf-8', errors='ignore')
                            if isinstance(ts_raw, str):
                                s = ts_raw
                                if s.endswith("Z"):
                                    s = s[:-1]
                                try:
                                    dt = datetime.fromisoformat(s)
                                    if dt.tzinfo is None:
                                        dt = dt.replace(tzinfo=timezone.utc)
                                    ist_dt = dt.astimezone(timezone(timedelta(hours=5, minutes=30)))
                                    ist_ts = ist_dt.strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    # try parsing as plain string fallback
                                    ist_ts = ts_raw
                            else:
                                # numeric or other type: stringify
                                ist_ts = str(ts_raw)
                        else:
                            ist_ts = None
                    except Exception:
                        ist_ts = ts_raw

                    # choose filename preferring original_filename then saved_filename
                    filename = orig_fn or saved_fn or None

                    # parse details JSON if possible
                    details_val = None
                    try:
                        if details_raw:
                            if isinstance(details_raw, str):
                                details_val = json.loads(details_raw)
                            else:
                                details_val = details_raw
                    except Exception:
                        details_val = details_raw

                    entries.append({
                        "id": id_,
                        "ts": ist_ts,
                        "case_id": caseid,
                        "artifact_id": aid,
                        "filename": filename,
                        "actor": actor,
                        "action": action,
                        "details": details_val,
                        "signature": signature
                    })
                con.close()
            except Exception:
                # final fallback: empty list
                entries = []

        return render_template("coc_case.html", case_id=case_id, entries=entries)
    except Exception:
        logger.exception("Failed to render case-level CoC for %s", case_id)
        return render_template("coc_case.html", case_id=case_id, entries=[]), 500


# ----------------------------
# Signup helper
# ----------------------------
import re
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import uuid

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _is_strong_password(pw: str) -> bool:
    """Basic policy: at least 12 chars. Extend as needed."""
    if not pw:
        return False
    if len(pw) < 12:
        return False
    return True

def create_user_from_signup_form(req, data_dir=DATA_DIR):
    """
    Validate request.form / request.files coming from your signup template,
    save uploaded files into data/users_uploads/<email>/ and persist the user
    into users.json via save_users().
    Returns the saved user_record dict on success.

    Raises ValueError on validation errors.
    """
    # fields
    full_name = (req.form.get("fullName") or "").strip()
    rank = (req.form.get("rank") or "").strip()
    department = (req.form.get("department") or "").strip()
    badge = (req.form.get("badge") or "").strip()
    email = (req.form.get("email") or "").strip().lower()
    mobile = (req.form.get("mobile") or "").strip()
    emergency = (req.form.get("emergency") or "").strip()
    supervisor = (req.form.get("supervisorEmail") or "").strip().lower()
    jurisdiction = (req.form.get("jurisdiction") or "").strip()
    specialization = (req.form.get("specialization") or "").strip()
    password = req.form.get("password") or ""
    password_confirm = req.form.get("passwordConfirm") or ""
    sec_question = (req.form.get("secQuestion") or "").strip()

    # files
    id_upload = req.files.get("idUpload")
    pki_upload = req.files.get("pki")

    # validation
    if not email:
        raise ValueError("Email is required.")
    if not EMAIL_RE.match(email):
        raise ValueError("Invalid email address.")
    if not password:
        raise ValueError("Password is required.")
    if password != password_confirm:
        raise ValueError("Passwords do not match.")
    if not _is_strong_password(password):
        raise ValueError("Password must be at least 12 characters long.")

    # ensure uniqueness
    users = load_users()
    if email in users:
        raise ValueError("An account already exists with that email.")

    # save uploads
    user_dir = os.path.join(data_dir, "users_uploads", email.replace("@", "_"))
    os.makedirs(user_dir, exist_ok=True)

    id_path = None
    if id_upload and id_upload.filename:
        filename = secure_filename(id_upload.filename)
        ext = os.path.splitext(filename)[1]
        id_path = os.path.join(user_dir, f"official_id_{uuid.uuid4().hex}{ext}")
        id_upload.save(id_path)

    pki_path = None
    if pki_upload and pki_upload.filename:
        filename = secure_filename(pki_upload.filename)
        ext = os.path.splitext(filename)[1]
        pki_path = os.path.join(user_dir, f"public_key_{uuid.uuid4().hex}{ext}")
        pki_upload.save(pki_path)

    # build user record
    user_record = {
        "full_name": full_name,
        "rank": rank,
        "department": department,
        "badge": badge,
        "email": email,
        "mobile": mobile,
        "emergency": emergency,
        "supervisor_email": supervisor,
        "jurisdiction": jurisdiction,
        "specialization": specialization,
        "password_hash": generate_password_hash(password),
        "security_question_answer": sec_question,
        "id_upload": id_path,
        "pki_upload": pki_path,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }

    # persist
    users[email] = user_record
    save_users(users)

    return user_record

# --- Investigator Signup Helper ---


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            create_user_from_signup_form(request)
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(request.url)
        except Exception:
            logger.exception("Unexpected error during signup")
            flash("Unexpected error, please try again later.", "danger")
            return redirect(request.url)

        flash("Account created successfully! You can now sign in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    # support redirect back to next if provided
    next_url = request.args.get("next") or request.form.get("next") or url_for("dashboard")
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        users = load_users()
        u = users.get(email)
        if u and check_password_hash(u.get("password_hash", ""), password):
            session["user"] = {"email": email}
            flash("Signed in", "success")
            # safe redirect: don't redirect to external hosts
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "danger")
        # fallthrough to render template (GET-like)
    return render_template("login.html", next=next_url)

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Signed out", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
