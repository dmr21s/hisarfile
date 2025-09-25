import os
import re
import shutil
from datetime import datetime, timedelta
from typing import List, Dict

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_from_directory,
    abort,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# === Paths ===
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = r"C:\Users\Demirr\Desktop\hisaruniqfile"
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# === Permission levels ===
PERM_NONE = 0
PERM_READ = 1            # OKU
PERM_WRITE = 2           # OKUMA_YAZMA
PERM_FULL = 3            # TAM DENETIM

# === Users & per-folder permissions ===
# Klasör adlarını kendi dizinindeki KÖK klasör isimleriyle birebir yaz.
# '*' anahtarına PERM_FULL verirsen her yerde tam denetim olur.
USERS: Dict[str, Dict] = {
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
    normalized = subdir.strip().strip("/\\").replace("/", "\\")
    normalized = os.path.normpath(normalized)
    if os.path.isabs(normalized) or ":" in normalized:
        abort(400, description="Geçersiz klasör yolu.")
    parts = [p for p in normalized.split("\\") if p not in ("..", ".", "")]
    if not parts:
        return UPLOAD_ROOT
    target_dir = os.path.join(UPLOAD_ROOT, *parts)
    target_abs = os.path.abspath(target_dir)
    upload_abs = os.path.abspath(UPLOAD_ROOT)
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

    # --- Errors ---
    @app.errorhandler(400)
    def _400(e): return jsonify({"ok": False, "error": str(e.description)}), 400
    @app.errorhandler(401)
    def _401(e): return jsonify({"ok": False, "error": "Giriş gerekli."}), 401
    @app.errorhandler(403)
    def _403(e): return jsonify({"ok": False, "error": str(e.description)}), 403
    @app.errorhandler(404)
    def _404(e): return jsonify({"ok": False, "error": str(e.description)}), 404
    @app.errorhandler(500)
    def _500(e): return jsonify({"ok": False, "error": "Sunucu hatası."}), 500

    # --- Auth wall ---
    @app.before_request
    def _guard():
        if request.path.startswith("/static/"):
            return
        if request.path in {"/api/login", "/login", "/favicon.ico", "/robots.txt"}:
            return
        if _current_user() is None:
            return jsonify({"ok": False, "error": "Giriş gerekli."}), 401

    # --- Pages ---
    @app.route("/login", methods=["GET"])
    def login_page():
        return render_template("login.html") if os.path.exists(
            os.path.join(APP_ROOT, "templates", "login.html")
        ) else jsonify({"ok": True, "message": "POST /api/login ile giriş yapın."})

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
        session.permanent = True
        return jsonify({"ok": True, "user": username})

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        session.clear()
        return jsonify({"ok": True, "message": "Çıkış yapıldı."})

    @app.route("/")
    def index():
        return render_template("index.html")

    # --- API: folders (görünür olanlar) ---
    @app.route("/api/folders", methods=["GET"])
    @app.route("/folders", methods=["GET"])
    def api_folders():
        all_folders = [f for f in list_all_folders() if f.split("/")[0] not in EXCLUDED_DIRS]
        allowed_heads = set(_visible_heads())
        visible = []
        for f in all_folders:
            head = _head_of(f)
            if head == "" or head in allowed_heads:
                visible.append(f)
        return jsonify({"ok": True, "folders": sorted(set(visible))})

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

    # --- API: create folder ---
    @app.route("/api/folders", methods=["POST"])
    def api_create_folder():
        folder = (request.get_json(silent=True) or {}).get("folder", "").strip()
        if not folder:
            abort(400, description="Klasör adı gerekli.")
        _require_perm(folder, PERM_WRITE)
        os.makedirs(resolve_target_dir(folder), exist_ok=True)
        return jsonify({"ok": True, "folder": folder})

    @app.route("/api/<path:parent>/folders/<path:new_folder>", methods=["POST"])
    @app.route("/<path:parent>/folders/<path:new_folder>", methods=["POST"])
    def api_create_folder_by_path(parent: str, new_folder: str):
        full_rel = os.path.normpath(os.path.join(parent or "", new_folder or "")).replace("\\", "/")
        if not full_rel:
            abort(400, description="Klasör adı gerekli.")
        _require_perm(full_rel, PERM_WRITE)
        os.makedirs(resolve_target_dir(full_rel), exist_ok=True)
        return jsonify({"ok": True, "folder": full_rel})

    @app.route("/api/folders/<path:new_folder>", methods=["POST"])
    @app.route("/folders/<path:new_folder>", methods=["POST"])
    def api_create_root_folder_by_path(new_folder: str):
        new_folder = (new_folder or "").strip()
        if not new_folder:
            abort(400, description="Klasör adı gerekli.")
        full_rel = os.path.normpath(new_folder).replace("\\", "/")
        _require_perm(full_rel, PERM_WRITE)
        os.makedirs(resolve_target_dir(full_rel), exist_ok=True)
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
        return jsonify({"ok": True, "newPath": new_rel})

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
            save_path = os.path.join(target_dir, filename)
            upload_file.save(save_path)
            rel_final_folder = "" if not dest_rel_folder else dest_rel_folder
            rel_final_path = filename if not rel_final_folder else f"{rel_final_folder}/{filename}"
            results.append({"name": filename, "path": rel_final_path, "url": f"/{rel_final_path}"})
        return jsonify({"ok": True, "uploaded": results, "count": len(results)})

    # --- Upload by clean URL ---
    @app.route("/<path:dest_folder>", methods=["POST"])
    def upload_to_path(dest_folder: str):
        dest_folder = (dest_folder or "").strip().strip("/\\")
        first_segment = dest_folder.split("/", 1)[0].lower()
        if first_segment in {d.lower() for d in EXCLUDED_DIRS} or first_segment == "api":
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
                save_path = os.path.join(target_dir, filename)
                upload_file.save(save_path)
                rel_final_folder = "" if not dest_rel_folder else dest_rel_folder
                rel_final_path = filename if not rel_final_folder else f"{rel_final_folder}/{filename}"
                results.append({"name": filename, "path": rel_final_path, "url": f"/{rel_final_path}"})
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
        return jsonify({"ok": True, "message": "Yüklendi",
                        "file": {"name": filename, "path": rel_final_path, "url": f"/{rel_final_path}"}})

    # --- Serve or SPA ---
    @app.route("/<path:requested_path>", methods=["GET"])
    def serve_or_index(requested_path: str):
        if requested_path.startswith("api/") or requested_path in {"favicon.ico", "robots.txt"}:
            abort(404)
        try:
            first_segment = requested_path.split("/", 1)[0]
            if first_segment in EXCLUDED_DIRS:
                raise FileNotFoundError
            if os.path.basename(requested_path) in EXCLUDED_FILES:
                raise FileNotFoundError
            _, ext = os.path.splitext(requested_path)
            if ext.lower() in EXCLUDED_EXTENSIONS:
                raise FileNotFoundError

            _require_perm(requested_path, PERM_READ)

            _ = resolve_target_dir(os.path.dirname(requested_path))
            directory = os.path.join(UPLOAD_ROOT, os.path.dirname(requested_path))
            filename = os.path.basename(requested_path)
            full = os.path.join(directory, filename)
            if os.path.exists(full) and os.path.isfile(full):
                download = str(request.args.get("download", "")).lower()
                return send_from_directory(
                    directory,
                    path=filename,
                    as_attachment=download in {"1", "true", "yes"}
                )
        except Exception:
            pass
        return render_template("index.html")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
