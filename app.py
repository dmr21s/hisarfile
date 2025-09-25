import os
import re
import shutil
from datetime import datetime, timedelta
from typing import List, Dict
import json

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_from_directory,
    abort,
    session,
    redirect,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from log import AuditLogger

# === Paths ===
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = r"C:\Users\HİSARDATA\Desktop\hisaruniqfile"
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# === Permission levels ===
PERM_NONE = 0
PERM_READ = 1            # OKU
PERM_WRITE = 2           # OKUMA_YAZMA
PERM_FULL = 3            # TAM DENETIM

# === Users & per-folder permissions ===
# Klasör adlarını kendi dizinindeki KÖK klasör isimleriyle birebir yaz.
# '*' anahtarına PERM_FULL verirsen her yerde tam denetim olur.
DEFAULT_USERS: Dict[str, Dict] = {
    "admin": {
        "password_hash": generate_password_hash("admin123"),
        "perms": {"*": PERM_FULL},
    },
    "yonetim": {
        "password_hash": generate_password_hash("yonetim123"),
        "perms": {
            "yonetim": PERM_FULL,
            "ortak": PERM_WRITE,
            "kalite": PERM_READ,
            "planlama": PERM_READ,
            "üretim": PERM_READ,
            "mali işler": PERM_READ,
            "kys dökümantasyon": PERM_READ,
        },
    },
    "kalite": {
        "password_hash": generate_password_hash("kalite123"),
        "perms": {
            "kalite": PERM_FULL,
            "kys dökümantasyon": PERM_FULL,
            "ortak": PERM_WRITE,
            "yonetim": PERM_READ,
            "planlama": PERM_READ,
            "üretim": PERM_READ,
            "mali işler": PERM_READ,
        },
    },
    "planlama": {
        "password_hash": generate_password_hash("planlama123"),
        "perms": {
            "planlama": PERM_FULL,
            "ortak": PERM_WRITE,
            "yonetim": PERM_READ,
            "kalite": PERM_READ,
            "üretim": PERM_READ,
            "mali işler": PERM_READ,
            "kys dökümantasyon": PERM_READ,
        },
    },
    "uretim": {
        "password_hash": generate_password_hash("uretim123"),
        "perms": {
            "üretim": PERM_FULL,
            "ortak": PERM_WRITE,
            "yonetim": PERM_READ,
            "kalite": PERM_READ,
            "planlama": PERM_READ,
            "mali işler": PERM_READ,
            "kys dökümantasyon": PERM_READ,
        },
    },
    "muhasebe": {
        "password_hash": generate_password_hash("muhasebe123"),
        "perms": {
            "mali işler": PERM_FULL,
            "ortak": PERM_WRITE,
            "yonetim": PERM_READ,
            "kalite": PERM_READ,
            "planlama": PERM_READ,
            "üretim": PERM_READ,
            "kys dökümantasyon": PERM_READ,
        },
    },
}

# Persisted users file (JSON)
USERS_FILE = os.path.join(APP_ROOT, "users.json")
USERS: Dict[str, Dict] = {}

def _load_users() -> None:
    global USERS
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # basic validation
            if isinstance(data, dict):
                USERS = data
            else:
                USERS = DEFAULT_USERS.copy()
    except FileNotFoundError:
        USERS = DEFAULT_USERS.copy()
        _save_users()

def _save_users() -> None:
    tmp_path = USERS_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(USERS, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, USERS_FILE)

# === Static exclusions ===
EXCLUDED_DIRS = {"templates", "static", "__pycache__"}
EXCLUDED_FILES = {"de.py", "requirements.txt"}
EXCLUDED_EXTENSIONS = {".config"}

# === Auth helpers ===
def _current_user() -> Dict | None:
    username = session.get("user")
    return USERS.get(username) if username else None

def _head_of(rel_path: str) -> str:
    rel = (rel_path or "").strip().strip("/\\")
    return "" if not rel else rel.split("/", 1)[0]

def _perm_for_head(head: str) -> int:
    user = _current_user()
    if not user:
        return PERM_NONE
    perms = user.get("perms", {})
    if "*" in perms:
        return perms["*"]
    return perms.get(head, PERM_NONE)

def _require_perm(rel_path_or_head: str, needed: int):
    head = _head_of(rel_path_or_head)
    if head == "":  # kök için gösterim izni
        return
    if _perm_for_head(head) < needed:
        abort(403, description="Bu klasörde bu işlemi yapma yetkiniz yok.")

def _visible_heads() -> List[str]:
    """Kullanıcının en az OKU izni olan kök klasörleri."""
    user = _current_user()
    if not user:
        return []
    perms = user.get("perms", {})
    if "*" in perms:
        # mevcut tüm kök klasörler
        try:
            return [
                d for d in os.listdir(UPLOAD_ROOT)
                if os.path.isdir(os.path.join(UPLOAD_ROOT, d))
                and d not in EXCLUDED_DIRS and not d.startswith(".")
            ]
        except FileNotFoundError:
            return []
    return [h for h, lvl in perms.items() if lvl >= PERM_READ]

# === Utility functions ===
def resolve_target_dir(subdir: str | None) -> str:
    if not subdir:
        return UPLOAD_ROOT
    
    # Clean and normalize the path for Windows
    normalized = subdir.strip().strip("/\\")
    # Convert forward slashes to backslashes on Windows, keep forward slashes on Unix
    if os.name == 'nt':  # Windows
        normalized = normalized.replace("/", "\\")
    
    # Additional normalization
    normalized = os.path.normpath(normalized)
    
    # Security checks
    if os.path.isabs(normalized) or ":" in normalized:
        abort(400, description="Geçersiz klasör yolu.")
    
    # Split and clean path components
    if os.name == 'nt':  # Windows
        parts = [p for p in normalized.split("\\") if p not in ("..", ".", "")]
    else:  # Unix-like
        parts = [p for p in normalized.replace("\\", "/").split("/") if p not in ("..", ".", "")]
    
    if not parts:
        return UPLOAD_ROOT
    
    # Build target directory
    target_dir = os.path.join(UPLOAD_ROOT, *parts)
    
    # Security validation
    target_abs = os.path.abspath(target_dir)
    upload_abs = os.path.abspath(UPLOAD_ROOT)
    
    # Ensure target is within upload root
    if not target_abs.startswith(upload_abs + os.sep) and target_abs != upload_abs:
        abort(400, description="Geçersiz klasör yolu.")
    
    return target_dir

def list_all_folders() -> List[str]:
    folders = [""]
    for dirpath, dirnames, _ in os.walk(UPLOAD_ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]
        rel = os.path.relpath(dirpath, UPLOAD_ROOT)
        if rel == ".":
            continue
        rel_posix = rel.replace("\\", "/")
        if rel_posix.split("/")[0] not in EXCLUDED_DIRS:
            folders.append(rel_posix)
    return sorted(set(folders))

def list_files_in_folder(subdir: str | None) -> List[Dict[str, str]]:
    _require_perm(subdir or "", PERM_READ)
    target = resolve_target_dir(subdir)
    items: List[Dict[str, str]] = []
    try:
        for name in os.listdir(target):
            abs_path = os.path.join(target, name)
            if os.path.isdir(abs_path) or name in EXCLUDED_FILES:
                continue
            _, ext = os.path.splitext(name)
            if ext.lower() in EXCLUDED_EXTENSIONS:
                continue
            rel_folder = "" if not subdir else os.path.normpath(subdir).replace("\\", "/")
            rel_path = name if not rel_folder else f"{rel_folder}/{name}"
            stat = os.stat(abs_path)
            items.append({
                "name": name,
                "path": rel_path,
                "url": f"/{rel_path}",
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    except FileNotFoundError:
        abort(404, description="Klasör bulunamadı.")
    return sorted(items, key=lambda x: x["name"].lower())

def _unique_filename(directory: str, filename: str) -> str:
    name, ext = os.path.splitext(filename)
    counter = 1
    candidate = filename
    while os.path.exists(os.path.join(directory, candidate)):
        candidate = f"{name} ({counter}){ext}"
        counter += 1
    return candidate

def _validate_new_name(name: str) -> None:
    if not name.strip():
        abort(400, description="Yeni ad gerekli.")
    if re.search(r'[<>:\"/\\|?*]', name):
        abort(400, description="Geçersiz karakterler içeriyor.")
    if os.path.sep in name or (os.path.altsep and os.path.altsep in name):
        abort(400, description="Sadece dosya adı girilmeli.")

def _resolve_absolute_path(rel_path: str) -> str:
    rel_norm = (rel_path or "").strip().strip("/\\")
    if not rel_norm:
        abort(400, description="Yol gerekli.")
    _require_perm(rel_norm, PERM_READ)  # en az okumaya sahip olmalı
    parent_rel = os.path.dirname(rel_norm)
    _ = resolve_target_dir(parent_rel)
    abs_path = os.path.abspath(os.path.join(UPLOAD_ROOT, rel_norm.replace("/", os.path.sep)))
    upload_abs = os.path.abspath(UPLOAD_ROOT)
    if not abs_path.startswith(upload_abs + os.sep) and abs_path != upload_abs:
        abort(400, description="Geçersiz yol.")
    return abs_path

# === Flask app ===
def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(APP_ROOT, "templates"),
        static_folder=os.path.join(APP_ROOT, "static"),
    )
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-prod")
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)

    # Load users from disk
    _load_users()

    # --- Audit log ---
    LOG_FILE = os.path.join(APP_ROOT, "audit.log")
    audit = AuditLogger(LOG_FILE)

    def _log(action: str, details: Dict | None = None, status: int | None = None):
        audit.log(
            user=session.get("user"),
            ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            action=action,
            details=details,
            status=status,
            method=request.method,
            path=request.path,
        )

    # --- Errors ---
    @app.errorhandler(400)
    def _400(e): 
        error_msg = str(e.description) if hasattr(e, 'description') else "Hatalı istek"
        return jsonify({"ok": False, "error": error_msg}), 400
        
    @app.errorhandler(401)
    def _401(e): 
        return jsonify({"ok": False, "error": "Giriş gerekli."}), 401
        
    @app.errorhandler(403)
    def _403(e): 
        error_msg = str(e.description) if hasattr(e, 'description') else "Yetkisiz erişim"
        return jsonify({"ok": False, "error": error_msg}), 403
        
    @app.errorhandler(404)
    def _404(e): 
        # If it's an API request, return JSON error
        if request.path.startswith("/api/"):
            error_msg = str(e.description) if hasattr(e, 'description') else "Bulunamadı"
            return jsonify({"ok": False, "error": error_msg}), 404
        # For regular requests, try to serve the SPA
        return render_template("index.html")
        
    @app.errorhandler(500)
    def _500(e): 
        error_msg = str(e.description) if hasattr(e, 'description') else "Sunucu hatası"
        return jsonify({"ok": False, "error": error_msg}), 500

    # --- Auth wall ---
    @app.before_request
    def _guard():
        # Skip static files and auth endpoints
        if request.path.startswith("/static/"):
            return
        if request.path in {"/api/login", "/login", "/favicon.ico", "/robots.txt"}:
            return
            
        # Skip auth for assets that might be served from static folder
        if request.path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg')):
            return
            
        if _current_user() is None:
            # Eğer AJAX/API isteğiyse JSON döndür, değilse login sayfasına yönlendir
            if request.path.startswith("/api/") or request.headers.get("Accept", "").find("application/json") != -1:
                _log("unauthorized", {"reason": "auth_required", "api": request.path}, status=401)
                return jsonify({"ok": False, "error": "Giriş gerekli."}), 401
            else:
                _log("unauthorized", {"reason": "redirect_login", "api": request.path}, status=302)
                return redirect("/login")
        # Oturumun her istekte non-permanent kalmasını sağla
        session.permanent = False

    @app.after_request
    def _after(resp):
        try:
            # Skip static
            if not request.path.startswith("/static/"):
                _log("request", {"api": request.path, "query": request.query_string.decode("utf-8", "ignore")}, status=resp.status_code)
        except Exception:
            pass
        return resp

    # --- Pages ---
    @app.route("/login", methods=["GET"])
    def login_page():
        # Eğer kullanıcı zaten giriş yapmışsa ana sayfaya yönlendir
        if _current_user() is not None:
            return redirect("/")
        return render_template("login.html")

    @app.route("/api/login", methods=["POST"])
    def api_login():
        data = request.get_json(silent=True) or request.form or {}
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        user = USERS.get(username)
        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"ok": False, "error": "Kullanıcı adı/şifre hatalı."}), 401
        session.clear()
        session["user"] = username
        session.permanent = False  # Oturum, tarayıcı kapanınca sonlansın
        _log("login", {"api": "/api/login"})
        return jsonify({"ok": True, "user": username})

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        session.clear()
        _log("logout", {})
        return jsonify({"ok": True, "message": "Çıkış yapıldı."})

    @app.route("/")
    def index():
        # Kullanıcı giriş yapmamışsa login sayfasına yönlendir
        if _current_user() is None:
            return redirect("/login")
        return render_template("index.html")

    # --- Admin page (only for admin) ---
    @app.route("/admin", methods=["GET"])
    def admin_page():
        if session.get("user") != "admin":
            abort(403, description="Yetkisiz.")
        return render_template("admin.html")

    # --- API: folders (görünür olanlar) ---
    @app.route("/api/folders", methods=["GET"])
    @app.route("/folders", methods=["GET"])
    def api_folders():
        current_user = _current_user()
        username = session.get("user", "Kullanıcı") if current_user else "Bilinmiyor"
        is_admin = session.get("user") == "admin"
        all_folders = [f for f in list_all_folders() if f.split("/")[0] not in EXCLUDED_DIRS]
        allowed_heads = set(_visible_heads())
        visible = []
        for f in all_folders:
            head = _head_of(f)
            if head == "" or head in allowed_heads:
                visible.append(f)
        return jsonify({
            "ok": True, 
            "folders": sorted(set(visible)),
            "user": username,
            "isAdmin": is_admin
        })

    # --- Admin APIs (only admin) ---
    def _require_admin():
        if session.get("user") != "admin":
            abort(403, description="Yalnızca admin.")

    @app.route("/api/admin/users", methods=["GET"])
    def api_admin_users():
        _require_admin()
        # Do not leak password hashes unless needed; but admin can see hashes. We'll still omit them.
        users_out = {}
        for uname, info in USERS.items():
            users_out[uname] = {"perms": info.get("perms", {})}
        return jsonify({"ok": True, "users": users_out, "levels": {
            "NONE": PERM_NONE, "READ": PERM_READ, "WRITE": PERM_WRITE, "FULL": PERM_FULL
        }})

    @app.route("/api/admin/heads", methods=["GET"])
    def api_admin_heads():
        _require_admin()
        try:
            heads = [d for d in os.listdir(UPLOAD_ROOT)
                     if os.path.isdir(os.path.join(UPLOAD_ROOT, d))
                     and d not in EXCLUDED_DIRS and not d.startswith('.')]
        except FileNotFoundError:
            heads = []
        return jsonify({"ok": True, "heads": sorted(heads)})

    @app.route("/api/admin/create-user", methods=["POST"])
    def api_admin_create_user():
        _require_admin()
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        perms = data.get("perms") or {}
        if not username or not password:
            abort(400, description="Kullanıcı adı ve şifre gerekli.")
        if username in USERS:
            abort(400, description="Kullanıcı zaten var.")
        USERS[username] = {
            "password_hash": generate_password_hash(password),
            "perms": perms,
        }
        _save_users()
        return jsonify({"ok": True})

    @app.route("/api/admin/delete-user", methods=["POST"])
    def api_admin_delete_user():
        _require_admin()
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        if not username or username == "admin":
            abort(400, description="Bu kullanıcı silinemez.")
        if username not in USERS:
            abort(404, description="Kullanıcı bulunamadı.")
        USERS.pop(username, None)
        _save_users()
        return jsonify({"ok": True})

    @app.route("/api/admin/set-password", methods=["POST"])
    def api_admin_set_password():
        _require_admin()
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        if not username or not password:
            abort(400, description="Kullanıcı ve şifre gerekli.")
        if username not in USERS:
            abort(404, description="Kullanıcı bulunamadı.")
        USERS[username]["password_hash"] = generate_password_hash(password)
        _save_users()
        return jsonify({"ok": True})

    @app.route("/api/admin/set-perms", methods=["POST"])
    def api_admin_set_perms():
        _require_admin()
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        perms = data.get("perms") or {}
        if not username:
            abort(400, description="Kullanıcı gerekli.")
        if username not in USERS:
            abort(404, description="Kullanıcı bulunamadı.")
        if not isinstance(perms, dict):
            abort(400, description="Geçersiz perms.")
        USERS[username]["perms"] = perms
        _save_users()
        return jsonify({"ok": True})

    # --- Admin logs API ---
    @app.route("/api/admin/logs", methods=["GET"])
    def api_admin_logs():
        _require_admin()
        try:
            page = max(1, int(request.args.get("page", 1)))
            size = min(500, max(1, int(request.args.get("size", 10))))
        except ValueError:
            page, size = 1, 10
        total, entries = audit.read_paginated(page, size)
        return jsonify({"ok": True, "page": page, "size": size, "total": total, "entries": entries})

    # --- API: list files ---
    @app.route("/api/files", methods=["GET"])
    @app.route("/files", methods=["GET"])
    def api_files():
        folder = request.args.get("folder", default="", type=str)
        _require_perm(folder, PERM_READ)
        return jsonify({"ok": True, "folder": folder, "files": list_files_in_folder(folder)})

    @app.route("/api/<path:folder>/files", methods=["GET"])
    @app.route("/<path:folder>/files", methods=["GET"])
    def api_files_by_path(folder: str):
        _require_perm(folder, PERM_READ)
        return jsonify({"ok": True, "folder": folder, "files": list_files_in_folder(folder)})

    # --- API: search (scoped to current folder and subfolders) ---
    @app.route("/api/search", methods=["GET"])
    def api_search():
        query = (request.args.get("q", "") or "").strip()
        base_folder = request.args.get("folder", default="", type=str)
        _require_perm(base_folder, PERM_READ)
        if not query:
            return jsonify({"ok": True, "folders": [], "files": []})

        # Normalize start directory
        start_dir = resolve_target_dir(base_folder)
        start_rel_prefix = (base_folder or "").strip().strip("/\\").replace("\\", "/")

        q_lower = query.lower()
        found_folders = set()
        found_files = []

        for dirpath, dirnames, filenames in os.walk(start_dir):
            # Filter excluded dirs in-place
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith('.')]

            # Compute relative path from UPLOAD_ROOT for permission checks and result building
            abs_dir = os.path.abspath(dirpath)
            rel_dir = os.path.relpath(abs_dir, UPLOAD_ROOT).replace("\\", "/")
            if rel_dir == ".":
                rel_dir = ""

            # Skip directories the user cannot read (based on head)
            try:
                _require_perm(rel_dir or "", PERM_READ)
            except Exception:
                # If no permission, skip traversing deeper by clearing dirnames
                dirnames[:] = []
                continue

            # Folder name match (collect directories under base)
            for d in dirnames:
                if d.lower().find(q_lower) != -1:
                    child_rel = (f"{rel_dir}/{d}" if rel_dir else d)
                    head = _head_of(child_rel)
                    if head not in EXCLUDED_DIRS:
                        found_folders.add(child_rel)

            # Files match
            for name in filenames:
                if name in EXCLUDED_FILES:
                    continue
                _, ext = os.path.splitext(name)
                if ext.lower() in EXCLUDED_EXTENSIONS:
                    continue
                if name.lower().find(q_lower) == -1:
                    continue
                rel_folder = rel_dir
                rel_path = name if not rel_folder else f"{rel_folder}/{name}"
                try:
                    abs_path = os.path.join(UPLOAD_ROOT, rel_path.replace("/", os.path.sep))
                    stat = os.stat(abs_path)
                except OSError:
                    continue
                found_files.append({
                    "name": name,
                    "path": rel_path,
                    "url": f"/{rel_path}",
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })

        return jsonify({
            "ok": True,
            "query": query,
            "folder": base_folder,
            "folders": sorted(found_folders),
            "files": sorted(found_files, key=lambda x: x["name"].lower()),
        })

    # --- API: exists (check file/dir conflict) ---
    @app.route("/api/exists", methods=["GET"])
    def api_exists():
        # params: folder (relative), name, type=file|dir
        folder = (request.args.get("folder", "") or "").strip()
        name = (request.args.get("name", "") or "").strip()
        kind = (request.args.get("type", "file") or "file").lower()
        if not name:
            abort(400, description="Ad gerekli.")
        # permission based on target
        target_rel = os.path.normpath(os.path.join(folder, name)).replace("\\", "/")
        _require_perm(target_rel, PERM_READ)
        base_dir = resolve_target_dir(folder)
        path = os.path.join(base_dir, secure_filename(name))
        exists = os.path.exists(path)
        if exists:
            is_dir = os.path.isdir(path)
            if kind == "dir" and not is_dir:
                exists = False
            if kind == "file" and is_dir:
                exists = False
        return jsonify({"ok": True, "exists": bool(exists)})

    # --- API: create folder ---
    @app.route("/api/folders", methods=["POST"])
    def api_create_folder():
        payload = (request.get_json(silent=True) or {})
        folder = (payload.get("folder", "") or "").strip()
        if not folder:
            abort(400, description="Klasör adı gerekli.")
        _require_perm(folder, PERM_WRITE)
        target = resolve_target_dir(folder)
        if os.path.exists(target):
            abort(409, description="Aynı isimde klasör mevcut.")
        os.makedirs(target, exist_ok=True)
        _log("create_folder", {"api": "/api/folders", "folder": folder})
        return jsonify({"ok": True, "folder": folder})

    @app.route("/api/<path:parent>/folders/<path:new_folder>", methods=["POST"])
    @app.route("/<path:parent>/folders/<path:new_folder>", methods=["POST"])
    def api_create_folder_by_path(parent: str, new_folder: str):
        full_rel = os.path.normpath(os.path.join(parent or "", new_folder or "")).replace("\\", "/")
        if not full_rel:
            abort(400, description="Klasör adı gerekli.")
        _require_perm(full_rel, PERM_WRITE)
        target = resolve_target_dir(full_rel)
        if os.path.exists(target):
            abort(409, description="Aynı isimde klasör mevcut.")
        os.makedirs(target, exist_ok=True)
        _log("create_folder", {"api": "/api/<parent>/folders/<new_folder>", "folder": full_rel})
        return jsonify({"ok": True, "folder": full_rel})

    @app.route("/api/folders/<path:new_folder>", methods=["POST"])
    @app.route("/folders/<path:new_folder>", methods=["POST"])
    def api_create_root_folder_by_path(new_folder: str):
        new_folder = (new_folder or "").strip()
        if not new_folder:
            abort(400, description="Klasör adı gerekli.")
        full_rel = os.path.normpath(new_folder).replace("\\", "/")
        _require_perm(full_rel, PERM_WRITE)
        target = resolve_target_dir(full_rel)
        if os.path.exists(target):
            abort(409, description="Aynı isimde klasör mevcut.")
        os.makedirs(target, exist_ok=True)
        _log("create_folder", {"api": "/api/folders/<new_folder>", "folder": full_rel})
        return jsonify({"ok": True, "folder": full_rel})

    # --- API: delete ---
    @app.route("/api/delete", methods=["POST"])
    def api_delete():
        rel_path = (request.get_json(silent=True) or {}).get("path", "").strip()
        if not rel_path:
            abort(400, description="Kök klasör silinemez.")
        _require_perm(rel_path, PERM_FULL)
        abs_path = _resolve_absolute_path(rel_path)
        head = rel_path.split("/", 1)[0]
        if head in EXCLUDED_DIRS or os.path.basename(rel_path) in EXCLUDED_FILES:
            abort(400, description="Bu öğe silinemez.")
        _, ext = os.path.splitext(rel_path)
        if ext.lower() in EXCLUDED_EXTENSIONS:
            abort(400, description="Bu öğe silinemez.")
        if not os.path.exists(abs_path):
            abort(404, description="Öğe bulunamadı.")
        try:
            shutil.rmtree(abs_path) if os.path.isdir(abs_path) else os.remove(abs_path)
        except OSError:
            abort(500, description="Silme işlemi başarısız.")
        _log("delete", {"api": "/api/delete", "path": rel_path})
        return jsonify({"ok": True})

    @app.route("/api/delete/<path:rel_path>", methods=["POST"])
    @app.route("/delete/<path:rel_path>", methods=["POST"])
    def api_delete_by_path(rel_path: str):
        rel_path = (rel_path or "").strip()
        if not rel_path:
            abort(400, description="Kök klasör silinemez.")
        _require_perm(rel_path, PERM_FULL)
        abs_path = _resolve_absolute_path(rel_path)
        head = rel_path.split("/", 1)[0]
        if head in EXCLUDED_DIRS or os.path.basename(rel_path) in EXCLUDED_FILES:
            abort(400, description="Bu öğe silinemez.")
        _, ext = os.path.splitext(rel_path)
        if ext.lower() in EXCLUDED_EXTENSIONS:
            abort(400, description="Bu öğe silinemez.")
        if not os.path.exists(abs_path):
            abort(404, description="Öğe bulunamadı.")
        try:
            shutil.rmtree(abs_path) if os.path.isdir(abs_path) else os.remove(abs_path)
        except OSError:
            abort(500, description="Silme işlemi başarısız.")
        _log("delete", {"api": "/api/delete/<path>", "path": rel_path})
        return jsonify({"ok": True})

    # --- API: rename ---
    @app.route("/api/rename", methods=["POST"])
    def api_rename():
        data = request.get_json(silent=True) or {}
        rel_path, new_name = data.get("path", "").strip(), data.get("newName", "").strip()
        if not rel_path:
            abort(400, description="Yol gerekli.")
        _require_perm(rel_path, PERM_FULL)
        _validate_new_name(new_name)
        abs_old = _resolve_absolute_path(rel_path)
        if not os.path.exists(abs_old):
            abort(404, description="Öğe bulunamadı.")
        parent_dir = os.path.dirname(abs_old)
        new_base = os.path.splitext(secure_filename(new_name))[0]
        if not new_base:
            abort(400, description="Geçersiz yeni ad.")
        final_name = new_base if os.path.isdir(abs_old) else f"{new_base}{os.path.splitext(abs_old)[1]}"
        abs_new = os.path.join(parent_dir, final_name)
        if os.path.exists(abs_new):
            abort(400, description="Bu ad zaten var.")
        try:
            os.rename(abs_old, abs_new)
        except OSError:
            abort(500, description="Yeniden adlandırma başarısız.")
        new_rel = os.path.relpath(abs_new, UPLOAD_ROOT).replace("\\", "/")
        _log("rename", {"api": "/api/rename", "old": rel_path, "new": new_rel})
        return jsonify({"ok": True, "newPath": new_rel})

    @app.route("/api/rename/<path:rel_path>", methods=["POST"])
    @app.route("/rename/<path:rel_path>", methods=["POST"])
    def api_rename_by_path(rel_path: str):
        data = request.get_json(silent=True) or {}
        new_name = (data.get("newName", "") or "").strip()
        if not rel_path:
            abort(400, description="Yol gerekli.")
        _require_perm(rel_path, PERM_FULL)
        _validate_new_name(new_name)
        abs_old = _resolve_absolute_path(rel_path)
        if not os.path.exists(abs_old):
            abort(404, description="Öğe bulunamadı.")
        parent_dir = os.path.dirname(abs_old)
        new_base = os.path.splitext(secure_filename(new_name))[0]
        if not new_base:
            abort(400, description="Geçersiz yeni ad.")
        final_name = new_base if os.path.isdir(abs_old) else f"{new_base}{os.path.splitext(abs_old)[1]}"
        abs_new = os.path.join(parent_dir, final_name)
        if os.path.exists(abs_new):
            abort(400, description="Bu ad zaten var.")
        try:
            os.rename(abs_old, abs_new)
        except OSError:
            abort(500, description="Yeniden adlandırma başarısız.")
        new_rel = os.path.relpath(abs_new, UPLOAD_ROOT).replace("\\", "/")
        _log("rename", {"api": "/api/rename/<path>", "old": rel_path, "new": new_rel})
        return jsonify({"ok": True, "newPath": new_rel})

    # --- API: move/copy ---
    def _validate_move_copy(src_rel: str, dest_folder_rel: str, new_name: str | None = None):
        src_rel = (src_rel or "").strip().strip("/\\")
        dest_folder_rel = (dest_folder_rel or "").strip()
        if not src_rel:
            abort(400, description="Kaynak yol gerekli.")
        # permissions
        # for move the caller will check FULL; for copy caller will check READ on src
        _ = resolve_target_dir(os.path.dirname(src_rel))
        dest_dir = resolve_target_dir(dest_folder_rel)
        os.makedirs(dest_dir, exist_ok=True)
        # compute abs
        src_abs = _resolve_absolute_path(src_rel)
        base_name = os.path.basename(src_abs)
        final_name = secure_filename(new_name) if new_name else base_name
        if not final_name:
            abort(400, description="Geçersiz hedef ad.")
        dest_abs = os.path.join(dest_dir, final_name)
        # prevent moving into own subtree
        src_abs_norm = os.path.abspath(src_abs)
        dest_abs_norm = os.path.abspath(dest_abs)
        if os.path.isdir(src_abs_norm):
            if dest_abs_norm.startswith(src_abs_norm + os.sep):
                abort(400, description="Bir klasörü kendi altına taşıyamazsınız.")
        return src_abs, dest_abs, final_name

    @app.route("/api/move", methods=["POST"])
    def api_move():
        data = request.get_json(silent=True) or {}
        src_rel = (data.get("path") or "").strip()
        dest_folder_rel = (data.get("destFolder") or "").strip()
        new_name = (data.get("newName") or "").strip() or None
        _require_perm(src_rel, PERM_FULL)
        _require_perm(dest_folder_rel, PERM_WRITE)
        src_abs, dest_abs, final_name = _validate_move_copy(src_rel, dest_folder_rel, new_name)
        if not os.path.exists(src_abs):
            abort(404, description="Kaynak bulunamadı.")
        if os.path.exists(dest_abs):
            abort(409, description="Hedefte aynı ad mevcut.")
        try:
            shutil.move(src_abs, dest_abs)
        except Exception:
            abort(500, description="Taşıma başarısız.")
        new_rel = os.path.relpath(dest_abs, UPLOAD_ROOT).replace("\\", "/")
        _log("move", {"api": "/api/move", "from": src_rel, "to": new_rel})
        return jsonify({"ok": True, "path": new_rel})

    @app.route("/api/copy", methods=["POST"])
    def api_copy():
        data = request.get_json(silent=True) or {}
        src_rel = (data.get("path") or "").strip()
        dest_folder_rel = (data.get("destFolder") or "").strip()
        new_name = (data.get("newName") or "").strip() or None
        _require_perm(src_rel, PERM_READ)
        _require_perm(dest_folder_rel, PERM_WRITE)
        src_abs, dest_abs, final_name = _validate_move_copy(src_rel, dest_folder_rel, new_name)
        if not os.path.exists(src_abs):
            abort(404, description="Kaynak bulunamadı.")
        if os.path.exists(dest_abs):
            abort(409, description="Hedefte aynı ad mevcut.")
        try:
            if os.path.isdir(src_abs):
                shutil.copytree(src_abs, dest_abs)
            else:
                os.makedirs(os.path.dirname(dest_abs), exist_ok=True)
                shutil.copy2(src_abs, dest_abs)
        except Exception:
            abort(500, description="Kopyalama başarısız.")
        new_rel = os.path.relpath(dest_abs, UPLOAD_ROOT).replace("\\", "/")
        _log("copy", {"api": "/api/copy", "from": src_rel, "to": new_rel})
        return jsonify({"ok": True, "path": new_rel})

    # --- API: upload(s) ---
    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        upload_file = request.files.get("file")
        if not upload_file or upload_file.filename == "":
            abort(400, description="Dosya yüklenmedi.")
        folder = request.form.get("folder", "").strip()
        rel_path = request.form.get("relativePath", "").strip()
        dest_rel_folder = (
            os.path.normpath(os.path.join(folder, os.path.dirname(rel_path))).replace("\\", "/")
            if rel_path else folder
        )
        _require_perm(dest_rel_folder, PERM_WRITE)
        target_dir = resolve_target_dir(dest_rel_folder)
        os.makedirs(target_dir, exist_ok=True)
        base_name = os.path.basename(rel_path) if rel_path else upload_file.filename
        filename = secure_filename(base_name)
        if not filename:
            abort(400, description="Geçersiz dosya adı.")
        save_path = os.path.join(target_dir, filename)
        upload_file.save(save_path)
        rel_folder = "" if not dest_rel_folder else os.path.normpath(dest_rel_folder).replace("\\", "/")
        rel_final_path = filename if not rel_folder else f"{rel_folder}/{filename}"
        _log("upload", {"api": "/api/upload", "path": rel_final_path, "folder": dest_rel_folder})
        return jsonify({"ok": True, "message": "Yüklendi",
                        "file": {"name": filename, "path": rel_final_path, "url": f"/{rel_final_path}"}})

    @app.route("/api/upload-batch", methods=["POST"])
    def api_upload_batch():
        files = request.files.getlist("file")
        if not files:
            abort(400, description="Dosya yüklenmedi.")
        rel_paths = request.form.getlist("relativePath")
        folder = request.form.get("folder", "").strip()
        results = []
        for idx, upload_file in enumerate(files):
            rel_path = rel_paths[idx] if idx < len(rel_paths) else upload_file.filename
            rel_path = (rel_path or "").strip().strip("/\\")
            dest_rel_folder = os.path.normpath(os.path.join(folder, os.path.dirname(rel_path))).replace("\\", "/")
            _require_perm(dest_rel_folder, PERM_WRITE)
            target_dir = resolve_target_dir(dest_rel_folder)
            os.makedirs(target_dir, exist_ok=True)
            base_name = os.path.basename(rel_path) if rel_path else upload_file.filename
            filename = secure_filename(base_name)
            if not filename:
                continue
            conflict = (request.form.get("conflict", "") or "").lower()
            save_name = filename
            save_path = os.path.join(target_dir, save_name)
            if os.path.exists(save_path):
                if conflict == "cancel":
                    continue
                elif conflict == "rename" or conflict == "":
                    save_name = _unique_filename(target_dir, filename)
                    save_path = os.path.join(target_dir, save_name)
                elif conflict == "overwrite":
                    pass
            upload_file.save(save_path)
            rel_final_folder = "" if not dest_rel_folder else dest_rel_folder
            rel_final_path = save_name if not rel_final_folder else f"{rel_final_folder}/{save_name}"
            _log("upload", {"api": "/api/upload-batch", "path": rel_final_path, "folder": dest_rel_folder, "conflict": conflict or "auto-rename"})
            results.append({"name": save_name, "path": rel_final_path, "url": f"/{rel_final_path}"})
        return jsonify({"ok": True, "uploaded": results, "count": len(results)})

    # --- Upload by clean URL ---
    @app.route("/<path:dest_folder>", methods=["POST"])
    def upload_to_path(dest_folder: str):
        # Clean and normalize the destination folder path
        dest_folder = (dest_folder or "").strip().strip("/\\")
        # Normalize path separators for current OS
        dest_folder = dest_folder.replace("\\", "/")  # Always use forward slashes internally
        
        first_segment = dest_folder.split("/", 1)[0].lower() if dest_folder else ""
        
        # Check for excluded directories and API paths
        if first_segment in {d.lower() for d in EXCLUDED_DIRS} or first_segment == "api" or first_segment == "admin":
            abort(404)
            
        _require_perm(dest_folder, PERM_WRITE)

        files = request.files.getlist("file")
        if files:
            rel_paths = request.form.getlist("relativePath")
            results = []
            for idx, upload_file in enumerate(files):
                rel_path = rel_paths[idx] if idx < len(rel_paths) else upload_file.filename
                rel_path = (rel_path or "").strip().strip("/\\")
                dest_rel_folder = os.path.normpath(os.path.join(dest_folder, os.path.dirname(rel_path))).replace("\\", "/")
                _require_perm(dest_rel_folder, PERM_WRITE)
                target_dir = resolve_target_dir(dest_rel_folder)
                os.makedirs(target_dir, exist_ok=True)
                base_name = os.path.basename(rel_path) if rel_path else upload_file.filename
                filename = secure_filename(base_name)
                if not filename:
                    continue
                conflict = (request.form.get("conflict", "") or "").lower()
                save_name = filename
                save_path = os.path.join(target_dir, save_name)
                if os.path.exists(save_path):
                    if conflict == "cancel":
                        continue
                    elif conflict == "rename" or conflict == "":
                        save_name = _unique_filename(target_dir, filename)
                        save_path = os.path.join(target_dir, save_name)
                    elif conflict == "overwrite":
                        pass
                upload_file.save(save_path)
                rel_final_folder = "" if not dest_rel_folder else dest_rel_folder
                rel_final_path = save_name if not rel_final_folder else f"{rel_final_folder}/{save_name}"
                _log("upload", {"api": "/<dest_folder> (POST)", "path": rel_final_path, "folder": dest_rel_folder, "conflict": conflict or "auto-rename"})
                results.append({"name": save_name, "path": rel_final_path, "url": f"/{rel_final_path}"})
            return jsonify({"ok": True, "uploaded": results, "count": len(results)})

        upload_file = request.files.get("file")
        if not upload_file or upload_file.filename == "":
            abort(400, description="Dosya yüklenmedi.")
        rel_path = (request.form.get("relativePath", "") or "").strip()
        dest_rel_folder = (
            os.path.normpath(os.path.join(dest_folder, os.path.dirname(rel_path))).replace("\\", "/")
            if rel_path else dest_folder
        )
        _require_perm(dest_rel_folder, PERM_WRITE)
        target_dir = resolve_target_dir(dest_rel_folder)
        os.makedirs(target_dir, exist_ok=True)
        base_name = os.path.basename(rel_path) if rel_path else upload_file.filename
        filename = secure_filename(base_name)
        if not filename:
            abort(400, description="Geçersiz dosya adı.")
        save_path = os.path.join(target_dir, filename)
        upload_file.save(save_path)
        rel_folder = "" if not dest_rel_folder else dest_rel_folder
        rel_final_path = filename if not rel_folder else f"{rel_folder}/{filename}"
        _log("upload", {"api": "/<dest_folder> (single)", "path": rel_final_path, "folder": dest_rel_folder})
        return jsonify({"ok": True, "message": "Yüklendi",
                        "file": {"name": filename, "path": rel_final_path, "url": f"/{rel_final_path}"}})

    # --- Chunked upload API (supports very large files) ---
    TMP_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, "_tmp_uploads")
    os.makedirs(TMP_UPLOAD_DIR, exist_ok=True)

    @app.route("/api/upload-chunk", methods=["POST"])
    def api_upload_chunk():
        # Fields: chunk(file), folder, relativePath, uploadId, chunkIndex, totalChunks, fileSize(optional)
        chunk_file = request.files.get("chunk")
        if not chunk_file:
            abort(400, description="Parça bulunamadı.")
        folder = (request.form.get("folder", "") or "").strip()
        rel_path = (request.form.get("relativePath", "") or "").strip()
        upload_id = (request.form.get("uploadId", "") or "").strip()
        try:
            chunk_index = int(request.form.get("chunkIndex", "0"))
            total_chunks = int(request.form.get("totalChunks", "1"))
        except ValueError:
            abort(400, description="Geçersiz parça bilgisi.")
        if not upload_id:
            abort(400, description="Upload ID gerekli.")

        dest_rel_folder = (
            os.path.normpath(os.path.join(folder, os.path.dirname(rel_path))).replace("\\", "/")
            if rel_path else folder
        )
        _require_perm(dest_rel_folder, PERM_WRITE)
        os.makedirs(TMP_UPLOAD_DIR, exist_ok=True)

        # Temp target: one file per upload id
        tmp_target = os.path.join(TMP_UPLOAD_DIR, secure_filename(upload_id) + ".part")

        # Append chunk sequentially
        try:
            with open(tmp_target, "ab") as f:
                chunk_file.stream.seek(0)
                shutil.copyfileobj(chunk_file.stream, f)
        except OSError:
            abort(500, description="Parça yazılamadı.")

        is_last = (chunk_index + 1) >= total_chunks
        if is_last:
            # Move assembled file to final location
            target_dir = resolve_target_dir(dest_rel_folder)
            os.makedirs(target_dir, exist_ok=True)
            base_name = os.path.basename(rel_path) if rel_path else "uploaded"
            filename = secure_filename(base_name)
            if not filename:
                abort(400, description="Geçersiz dosya adı.")
            conflict = (request.form.get("conflict", "") or "").lower()
            save_name = filename
            final_path = os.path.join(target_dir, save_name)
            if os.path.exists(final_path):
                if conflict == "cancel":
                    abort(409, description="Dosya mevcut.")
                elif conflict == "rename" or conflict == "":
                    save_name = _unique_filename(target_dir, filename)
                    final_path = os.path.join(target_dir, save_name)
                elif conflict == "overwrite":
                    pass
            try:
                os.replace(tmp_target, final_path)
            except OSError:
                abort(500, description="Dosya birleştirme hatası.")
            rel_folder = "" if not dest_rel_folder else dest_rel_folder
            rel_final_path = save_name if not rel_folder else f"{rel_folder}/{save_name}"
            _log("upload_chunk_done", {"api": "/api/upload-chunk", "path": rel_final_path, "folder": dest_rel_folder, "chunks": total_chunks, "conflict": conflict or "auto-rename"})
            return jsonify({"ok": True, "done": True, "file": {"name": save_name, "path": rel_final_path, "url": f"/{rel_final_path}"}})

        return jsonify({"ok": True, "done": False, "received": chunk_index})

    # --- Static files route (ensure this comes before catch-all) ---
    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(app.static_folder, "favicon.ico") if os.path.exists(os.path.join(app.static_folder, "favicon.ico")) else abort(404)

    @app.route("/robots.txt")
    def robots():
        return "User-agent: *\nDisallow: /", 200, {"Content-Type": "text/plain"}

    # --- Serve or SPA ---
    @app.route("/<path:requested_path>", methods=["GET"])
    def serve_or_index(requested_path: str):
        # Normalize the path for Windows
        requested_path = requested_path.replace("\\", "/")
        
        # Handle API and special paths first
        if requested_path.startswith("api/") or requested_path in {"favicon.ico", "robots.txt"}:
            abort(404)
        
        # Handle admin route specifically
        if requested_path == "admin":
            return redirect("/admin")
            
        try:
            first_segment = requested_path.split("/", 1)[0] if "/" in requested_path else requested_path
            
            # Check if this is an excluded directory
            if first_segment.lower() in {d.lower() for d in EXCLUDED_DIRS}:
                raise FileNotFoundError
            
            # Check if this is an excluded file
            if os.path.basename(requested_path) in EXCLUDED_FILES:
                raise FileNotFoundError
                
            # Check file extension
            _, ext = os.path.splitext(requested_path)
            if ext.lower() in EXCLUDED_EXTENSIONS:
                raise FileNotFoundError

            # Check permissions
            _require_perm(requested_path, PERM_READ)

            # Resolve and validate paths with Windows compatibility
            parent_dir = os.path.dirname(requested_path) if "/" in requested_path else ""
            _ = resolve_target_dir(parent_dir)
            
            # Build full path with proper Windows path handling
            if parent_dir:
                directory = os.path.join(UPLOAD_ROOT, parent_dir.replace("/", os.path.sep))
            else:
                directory = UPLOAD_ROOT
                
            filename = os.path.basename(requested_path)
            full_path = os.path.join(directory, filename)
            
            # Normalize and check if file exists
            full_path = os.path.normpath(full_path)
            if os.path.exists(full_path) and os.path.isfile(full_path):
                download = str(request.args.get("download", "")).lower()
                return send_from_directory(
                    directory,
                    filename,
                    as_attachment=download in {"1", "true", "yes"}
                )
        except Exception as e:
            # Log the exception for debugging
            print(f"File serve error for '{requested_path}': {e}")
            pass
            
        # Fallback to SPA
        return render_template("index.html")

    return app


app = create_app()

if __name__ == "__main__":
    import logging
    
    # Configure logging for better debugging on Windows server
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('app.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting Hisar Uniq File Manager")
    logger.info(f"Upload root: {UPLOAD_ROOT}")
    logger.info(f"Operating system: {os.name}")
    
    # Ensure upload directory exists
    try:
        os.makedirs(UPLOAD_ROOT, exist_ok=True)
        logger.info(f"Upload directory verified: {UPLOAD_ROOT}")
    except Exception as e:
        logger.error(f"Failed to create upload directory: {e}")
    
    app.run(host="0.0.0.0", port=5000, debug=False)
