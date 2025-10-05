# modules/auth.py
import os
import json
import hashlib
import binascii
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory

MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
USERS_DIR = os.path.join(DATA_DIR, "users")
os.makedirs(USERS_DIR, exist_ok=True)

bp = Blueprint("auth", __name__, template_folder="../templates")

# simple password hashing (PBKDF2) for demo only
def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return binascii.hexlify(salt).decode() + "$" + binascii.hexlify(dk).decode()

def verify_password(stored_hash: str, candidate: str) -> bool:
    try:
        salt_hex, dk_hex = stored_hash.split("$")
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(dk_hex)
        cand = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, 100_000)
        return cand == expected
    except Exception:
        return False

def safe_user_path(email: str):
    # make filename safe for storage (use email-based key)
    safe = secure_filename(email.replace("@", "_at_"))
    return os.path.join(USERS_DIR, f"{safe}.json")

@bp.route("/signup", methods=["GET"])
def signup_get():
    return render_template("signup.html")

@bp.route("/signup", methods=["POST"])
def signup_post():
    # Basic form processing and minimal validation
    form = request.form
    files = request.files

    fullName = form.get("fullName", "").strip()
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    passwordConfirm = form.get("passwordConfirm", "")
    mobile = form.get("mobile", "").strip()

    # Required checks
    errors = []
    if not fullName:
        errors.append("Full name is required.")
    if not email:
        errors.append("Official email is required.")
    if not password or len(password) < 12:
        errors.append("Password is required (minimum 12 characters).")
    if password != passwordConfirm:
        errors.append("Passwords do not match.")

    # file checks (idUpload is required per your spec)
    id_upload = files.get("idUpload")
    if id_upload and id_upload.filename:
        id_fn = secure_filename(id_upload.filename)
    else:
        errors.append("Official ID proof (file) is required.")

    if errors:
        # Render page again with errors
        return render_template("signup.html", errors=errors, form=form), 400

    # Persist files and user record
    user_path = safe_user_path(email)
    userdir = os.path.dirname(user_path)
    os.makedirs(userdir, exist_ok=True)

    saved_id_path = None
    saved_pki_path = None
    try:
        # store ID upload
        if id_upload and id_upload.filename:
            id_dest_dir = os.path.join(USERS_DIR, secure_filename(email.replace("@", "_at_")))
            os.makedirs(id_dest_dir, exist_ok=True)
            saved_id_path = os.path.join(id_dest_dir, "id_" + secure_filename(id_upload.filename))
            id_upload.save(saved_id_path)

        pki = files.get("pki")
        if pki and pki.filename:
            pki_dest_dir = os.path.join(USERS_DIR, secure_filename(email.replace("@", "_at_")))
            os.makedirs(pki_dest_dir, exist_ok=True)
            saved_pki_path = os.path.join(pki_dest_dir, "pki_" + secure_filename(pki.filename))
            pki.save(saved_pki_path)
    except Exception as e:
        current_app.logger.exception("Failed saving uploaded files for signup")
        errors.append("Failed saving uploaded files.")
        return render_template("signup.html", errors=errors, form=form), 500

    # create user record
    record = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "fullName": fullName,
        "rank": form.get("rank"),
        "department": form.get("department"),
        "badge": form.get("badge"),
        "email": email,
        "mobile": mobile,
        "emergency": form.get("emergency"),
        "supervisorEmail": form.get("supervisorEmail"),
        "jurisdiction": form.get("jurisdiction"),
        "specialization": form.get("specialization"),
        "mfaPreference": form.get("mfaPreference"),
        "secQuestion": form.get("secQuestion"),
        "idUploadPath": saved_id_path,
        "pkiPath": saved_pki_path,
        # hashed password
        "password_hash": hash_password(password)
    }

    # Write user file atomically
    tmp = user_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
        os.replace(tmp, user_path)
    except Exception:
        current_app.logger.exception("Failed writing user record")
        errors.append("Failed writing user record.")
        return render_template("signup.html", errors=errors, form=form), 500

    # success — redirect to login or show success message
    return render_template("signup_success.html", email=email)

@bp.route("/login", methods=["GET"])
def login_get():
    return render_template("login.html")

@bp.route("/login", methods=["POST"])
def login_post():
    form = request.form
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    user_path = safe_user_path(email)
    if not os.path.exists(user_path):
        return render_template("login.html", error="Unknown user."), 401

    try:
        with open(user_path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
    except Exception:
        return render_template("login.html", error="Failed to load user record."), 500

    if verify_password(rec.get("password_hash", ""), password):
        # For demo just redirect to dashboard; in real app set session
        return redirect(url_for("dashboard", case_id="case001"))
    else:
        return render_template("login.html", error="Invalid credentials."), 401

@bp.route("/users/<email>/files/<filename>")
def user_files(email, filename):
    # simple static file serve for uploaded files (demo-only)
    safe_dir = os.path.join(USERS_DIR, secure_filename(email.replace("@","_at_")))
    return send_from_directory(safe_dir, filename)
