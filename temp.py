import os
import re
import shutil
from datetime import datetime
from typing import List, Dict

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_from_directory,
    abort,
)
from werkzeug.utils import secure_filename

# === Paths ===
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = r"C:\Users\Demirr\Desktop\hisaruniqfile"
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# === Exclusions ===
EXCLUDED_DIRS = {"templates", "static", "__pycache__"}
EXCLUDED_FILES = {"de.py", "requirements.txt"}
EXCLUDED_EXTENSIONS = {".config"}


# === Utility Functions ===
def resolve_target_dir(subdir: str | None) -> str:
    """Kullanıcının belirttiği klasörü UPLOAD_ROOT altında güvenli mutlak yola çevir."""
    if not subdir:
        return UPLOAD_ROOT

    normalized = subdir.strip().strip("/\\").replace("/", "\\")
    normalized = os.path.normpath(normalized)

    # Mutlak/disk yolu engelle
    if os.path.isabs(normalized) or ":" in normalized:
        abort(400, description="Geçersiz klasör yolu.")

    # Traversal engelle
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
    """UPLOAD_ROOT altında (uygulama klasörleri hariç) tüm klasörleri döndür (recursive)."""
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
    """Bir klasörün içindeki dosyaları (recursive değil) listele."""
    target = resolve_target_dir(subdir)
    items: List[Dict[str, str]] = []

    try:
        for name in os.listdir(target):
            abs_path = os.path.join(target, name)
            if os.path.isdir(abs_path) or name in EXCLUDED_FILES:
                continue

            # Check for excluded file extensions
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
    if re.search(r'[<>:"/\\|?*]', name):
        abort(400, description="Geçersiz karakterler içeriyor.")
    if os.path.sep in name or (os.path.altsep and os.path.altsep in name):
        abort(400, description="Sadece dosya adı girilmeli.")


def _resolve_absolute_path(rel_path: str) -> str:
    rel_norm = (rel_path or "").strip().strip("/\\")
    if not rel_norm:
        abort(400, description="Yol gerekli.")

    parent_rel = os.path.dirname(rel_norm)
    _ = resolve_target_dir(parent_rel)

    abs_path = os.path.abspath(os.path.join(UPLOAD_ROOT, rel_norm.replace("/", os.path.sep)))
    upload_abs = os.path.abspath(UPLOAD_ROOT)

    if not abs_path.startswith(upload_abs + os.sep) and abs_path != upload_abs:
        abort(400, description="Geçersiz yol.")

    return abs_path


# === Flask App ===
def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(APP_ROOT, "templates"),
        static_folder=os.path.join(APP_ROOT, "static"),
    )

    # === Error Handlers ===
    @app.errorhandler(400)
    def handle_400(err):
        return jsonify({"ok": False, "error": str(err.description)}), 400

    @app.errorhandler(404)
    def handle_404(err):
        return jsonify({"ok": False, "error": str(err.description)}), 404

    @app.errorhandler(500)
    def handle_500(err):
        return jsonify({"ok": False, "error": "Sunucu hatası."}), 500

    # === Public Routes (Auth kaldırıldı) ===
    @app.route("/")
    def index():
        return render_template("index.html")

    # === API Routes ===
    @app.route("/api/folders", methods=["GET"])
    @app.route("/folders", methods=["GET"])  # clean URL
    def api_folders():
        return jsonify({
            "ok": True,
            "folders": [f for f in list_all_folders() if f.split("/")[0] not in EXCLUDED_DIRS]
        })

    @app.route("/api/files", methods=["GET"])
    @app.route("/files", methods=["GET"])  # clean URL for root
    def api_files():
        folder = request.args.get("folder", default="", type=str)
        return jsonify({"ok": True, "folder": folder, "files": list_files_in_folder(folder)})

    # Path-based: list files in folder via URL
    @app.route("/api/<path:folder>/files", methods=["GET"])
    @app.route("/<path:folder>/files", methods=["GET"])  # clean URL
    def api_files_by_path(folder: str):
        return jsonify({"ok": True, "folder": folder, "files": list_files_in_folder(folder)})

    @app.route("/api/folders", methods=["POST"])
    def api_create_folder():
        folder = (request.get_json(silent=True) or {}).get("folder", "").strip()
        if not folder:
            abort(400, description="Klasör adı gerekli.")
        os.makedirs(resolve_target_dir(folder), exist_ok=True)
        return jsonify({"ok": True, "folder": folder})

    # Path-based: create subfolder under URL-specified parent
    @app.route("/api/<path:parent>/folders/<path:new_folder>", methods=["POST"])
    @app.route("/<path:parent>/folders/<path:new_folder>", methods=["POST"])  # clean URL
    def api_create_folder_by_path(parent: str, new_folder: str):
        # Compose full relative path of the new folder
        full_rel = os.path.normpath(os.path.join(parent or "", new_folder or "")).replace("\\", "/")
        if not full_rel:
            abort(400, description="Klasör adı gerekli.")
        os.makedirs(resolve_target_dir(full_rel), exist_ok=True)
        return jsonify({"ok": True, "folder": full_rel})

    # Path-based: create folder at root
    @app.route("/api/folders/<path:new_folder>", methods=["POST"])
    @app.route("/folders/<path:new_folder>", methods=["POST"])  # clean URL
    def api_create_root_folder_by_path(new_folder: str):
        new_folder = (new_folder or "").strip()
        if not new_folder:
            abort(400, description="Klasör adı gerekli.")
        full_rel = os.path.normpath(new_folder).replace("\\", "/")
        os.makedirs(resolve_target_dir(full_rel), exist_ok=True)
        return jsonify({"ok": True, "folder": full_rel})

    @app.route("/api/delete", methods=["POST"])
    def api_delete():
        rel_path = (request.get_json(silent=True) or {}).get("path", "").strip()
        if not rel_path:
            abort(400, description="Kök klasör silinemez.")
        abs_path = _resolve_absolute_path(rel_path)

        head = rel_path.split("/", 1)[0]
        if head in EXCLUDED_DIRS or os.path.basename(rel_path) in EXCLUDED_FILES:
            abort(400, description="Bu öğe silinemez.")

        # Check for excluded file extensions
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

    # Path-based: delete by URL path
    @app.route("/api/delete/<path:rel_path>", methods=["POST"])
    @app.route("/delete/<path:rel_path>", methods=["POST"])  # clean URL
    def api_delete_by_path(rel_path: str):
        rel_path = (rel_path or "").strip()
        if not rel_path:
            abort(400, description="Kök klasör silinemez.")
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

    @app.route("/api/rename", methods=["POST"])
    def api_rename():
        data = request.get_json(silent=True) or {}
        rel_path, new_name = data.get("path", "").strip(), data.get("newName", "").strip()
        if not rel_path:
            abort(400, description="Yol gerekli.")
        _validate_new_name(new_name)

        abs_old = _resolve_absolute_path(rel_path)
        if not os.path.exists(abs_old):
            abort(404, description="Öğe bulunamadı.")

        parent_dir = os.path.dirname(abs_old)
        # Sadece ad değişsin, uzantı korunacak (dosyalar için)
        # Kullanıcı uzantı yazsa da yok sayılır; sadece taban ad kullanılır
        new_base = os.path.splitext(secure_filename(new_name))[0]
        if not new_base:
            abort(400, description="Geçersiz yeni ad.")

        if os.path.isdir(abs_old):
            final_name = new_base
        else:
            _, old_ext = os.path.splitext(abs_old)
            final_name = f"{new_base}{old_ext}"

        abs_new = os.path.join(parent_dir, final_name)

        if os.path.exists(abs_new):
            abort(400, description="Bu ad zaten var.")

        try:
            os.rename(abs_old, abs_new)
        except OSError:
            abort(500, description="Yeniden adlandırma başarısız.")

        new_rel = os.path.relpath(abs_new, UPLOAD_ROOT).replace("\\", "/")
        return jsonify({"ok": True, "newPath": new_rel})

    # Path-based: rename by URL path, with new name in body
    @app.route("/api/rename/<path:rel_path>", methods=["POST"])
    @app.route("/rename/<path:rel_path>", methods=["POST"])  # clean URL
    def api_rename_by_path(rel_path: str):
        data = request.get_json(silent=True) or {}
        new_name = (data.get("newName", "") or "").strip()
        if not rel_path:
            abort(400, description="Yol gerekli.")
        _validate_new_name(new_name)

        abs_old = _resolve_absolute_path(rel_path)
        if not os.path.exists(abs_old):
            abort(404, description="Öğe bulunamadı.")

        parent_dir = os.path.dirname(abs_old)
        new_base = os.path.splitext(secure_filename(new_name))[0]
        if not new_base:
            abort(400, description="Geçersiz yeni ad.")

        if os.path.isdir(abs_old):
            final_name = new_base
        else:
            _, old_ext = os.path.splitext(abs_old)
            final_name = f"{new_base}{old_ext}"

        abs_new = os.path.join(parent_dir, final_name)
        if os.path.exists(abs_new):
            abort(400, description="Bu ad zaten var.")
        try:
            os.rename(abs_old, abs_new)
        except OSError:
            abort(500, description="Yeniden adlandırma başarısız.")
        new_rel = os.path.relpath(abs_new, UPLOAD_ROOT).replace("\\", "/")
        return jsonify({"ok": True, "newPath": new_rel})

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        upload_file = request.files.get("file")
        if not upload_file or upload_file.filename == "":
            abort(400, description="Dosya yüklenmedi.")

        folder = request.form.get("folder", "").strip()
        rel_path = request.form.get("relativePath", "").strip()

        # Hedef klasörü belirle (relativePath varsa alt klasörleri oluştur)
        if rel_path:
            dest_rel_folder = os.path.normpath(os.path.join(folder, os.path.dirname(rel_path))).replace("\\", "/")
        else:
            dest_rel_folder = folder

        target_dir = resolve_target_dir(dest_rel_folder)
        os.makedirs(target_dir, exist_ok=True)

        # Güvenli dosya adı
        base_name = os.path.basename(rel_path) if rel_path else upload_file.filename
        filename = secure_filename(base_name)
        if not filename:
            abort(400, description="Geçersiz dosya adı.")

        save_path = os.path.join(target_dir, filename)
        upload_file.save(save_path)

        rel_folder = "" if not dest_rel_folder else os.path.normpath(dest_rel_folder).replace("\\", "/")
        rel_final_path = filename if not rel_folder else f"{rel_folder}/{filename}"

        return jsonify({
            "ok": True,
            "message": "Yüklendi",
            "file": {"name": filename, "path": rel_final_path, "url": f"/{rel_final_path}"}
        })

    @app.route("/api/upload-batch", methods=["POST"])
    def api_upload_batch():
        """
        Çoklu dosya/klasör yükleme.
        - FormData'da her dosya için:
          append('file', file)
          append('relativePath', 'alt/klasor/dosya.ext')
        - Ayrıca append('folder', 'mevcut/hedef') gönderilir.
        """
        files = request.files.getlist("file")
        if not files:
            abort(400, description="Dosya yüklenmedi.")
        rel_paths = request.form.getlist("relativePath")
        folder = request.form.get("folder", "").strip()

        results = []
        for idx, upload_file in enumerate(files):
            rel_path = rel_paths[idx] if idx < len(rel_paths) else upload_file.filename
            rel_path = (rel_path or "").strip().strip("/\\")
            dest_rel_folder = os.path.normpath(
                os.path.join(folder, os.path.dirname(rel_path))
            ).replace("\\", "/")

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

            results.append({
                "name": filename,
                "path": rel_final_path,
                "url": f"/{rel_final_path}"
            })

        return jsonify({"ok": True, "uploaded": results, "count": len(results)})

    # === Upload to folder specified in URL path ===
    @app.route("/<path:dest_folder>", methods=["POST"])
    def upload_to_path(dest_folder: str):
        """URL ile verilen klasöre (ör: POST /kalite/ss) yükleme yap.
        FormData:
          - Çoklu: file (tekrar eden), relativePath (tekrar eden)
          - Tekli: file, relativePath (opsiyonel)
        """
        # Clean and validate destination folder
        dest_folder = (dest_folder or "").strip().strip("/\\")
        # API yolları veya sabit dosyalar engellensin
        first_segment = dest_folder.split("/", 1)[0].lower()
        if first_segment in {d.lower() for d in EXCLUDED_DIRS} or first_segment == "api":
            abort(404)

        # Try batch first
        files = request.files.getlist("file")
        if files:
            rel_paths = request.form.getlist("relativePath")
            results = []
            for idx, upload_file in enumerate(files):
                rel_path = rel_paths[idx] if idx < len(rel_paths) else upload_file.filename
                rel_path = (rel_path or "").strip().strip("/\\")
                dest_rel_folder = os.path.normpath(
                    os.path.join(dest_folder, os.path.dirname(rel_path))
                ).replace("\\", "/")

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

                results.append({
                    "name": filename,
                    "path": rel_final_path,
                    "url": f"/{rel_final_path}"
                })

            return jsonify({"ok": True, "uploaded": results, "count": len(results)})

        # Fallback to single file
        upload_file = request.files.get("file")
        if not upload_file or upload_file.filename == "":
            abort(400, description="Dosya yüklenmedi.")
        rel_path = (request.form.get("relativePath", "") or "").strip()
        if rel_path:
            dest_rel_folder = os.path.normpath(os.path.join(dest_folder, os.path.dirname(rel_path))).replace("\\", "/")
        else:
            dest_rel_folder = dest_folder

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

        return jsonify({
            "ok": True,
            "message": "Yüklendi",
            "file": {"name": filename, "path": rel_final_path, "url": f"/{rel_final_path}"}
        })

    # === File Serving on Clean URLs ===
    @app.route("/<path:requested_path>", methods=["GET"])
    def serve_or_index(requested_path: str):
        # Block API/static/template/self paths
        if requested_path.startswith("api/") or requested_path in {"favicon.ico", "robots.txt"}:
            abort(404)

        # If the path points to a real uploaded file, serve it
        try:
            first_segment = requested_path.split("/", 1)[0].lower()
            if first_segment in {d.lower() for d in EXCLUDED_DIRS}:
                raise FileNotFoundError

            if os.path.basename(requested_path) in EXCLUDED_FILES:
                raise FileNotFoundError

            # Check for excluded file extensions
            _, ext = os.path.splitext(requested_path)
            if ext.lower() in EXCLUDED_EXTENSIONS:
                raise FileNotFoundError

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

        # Otherwise render SPA for folder navigation
        return render_template("index.html")

    # Note: catch-all is merged into serve_or_index above

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)