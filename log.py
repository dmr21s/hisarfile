import os
import json
from datetime import datetime
from typing import Dict, List, Tuple


class AuditLogger:
    def __init__(self, log_file: str):
        self.log_file = log_file
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def write(self, entry: Dict) -> None:
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            # Never raise from logger
            pass

    def _format_action_description(self, action: str, details: Dict) -> str:
        """Convert action and details into human-readable Turkish description"""
        if action == "login":
            return "✅ Sisteme giriş yapıldı"
        elif action == "logout":
            return "🚪 Sistemden çıkış yapıldı"
        elif action == "upload":
            path = details.get("path", "")
            folder = details.get("folder", "")
            conflict = details.get("conflict", "")
            
            # Make path more readable
            clean_path = path.replace("/", " → ") if "/" in path else path
            
            if conflict == "overwrite":
                return f"📤 Dosya değiştirildi: {clean_path} (eski dosyanın üzerine yazıldı)"
            elif conflict == "rename" or conflict == "auto-rename":
                return f"📤 Dosya yüklendi: {clean_path} (otomatik yeniden adlandırıldı)"
            else:
                return f"📤 Dosya yüklendi: {clean_path}"
                
        elif action == "upload_chunk_done":
            path = details.get("path", "")
            chunks = details.get("chunks", 1)
            clean_path = path.replace("/", " → ") if "/" in path else path
            return f"📤 Büyük dosya yüklendi: {clean_path} (toplam {chunks} parça halinde)"
        elif action == "delete":
            path = details.get("path", "")
            clean_path = path.replace("/", " → ") if "/" in path else path
            return f"🗑️ Silindi: {clean_path}"
        elif action == "rename":
            old_path = details.get("old", "")
            new_path = details.get("new", "")
            old_clean = old_path.replace("/", " → ") if "/" in old_path else old_path
            new_clean = new_path.replace("/", " → ") if "/" in new_path else new_path
            return f"✏️ Yeniden adlandırıldı: {old_clean} ➜ {new_clean}"
        elif action == "move":
            from_path = details.get("from", "")
            to_path = details.get("to", "")
            from_clean = from_path.replace("/", " → ") if "/" in from_path else from_path
            to_clean = to_path.replace("/", " → ") if "/" in to_path else to_path
            return f"📦 Taşındı: {from_clean} ➜ {to_clean}"
        elif action == "copy":
            from_path = details.get("from", "")
            to_path = details.get("to", "")
            from_clean = from_path.replace("/", " → ") if "/" in from_path else from_path
            to_clean = to_path.replace("/", " → ") if "/" in to_path else to_path
            return f"📋 Kopyalandı: {from_clean} ➜ {to_clean}"
        elif action == "create_folder":
            folder = details.get("folder", "")
            clean_folder = folder.replace("/", " → ") if "/" in folder else folder
            return f"📁 Yeni klasör oluşturuldu: {clean_folder}"
        elif action == "unauthorized":
            reason = details.get("reason", "")
            api = details.get("api", "")
            if reason == "auth_required":
                return f"⛔ Yetkisiz erişim girişimi: {api}"
            elif reason == "redirect_login":
                return "🔄 Giriş sayfasına yönlendirildi (oturum süresi dolmuş)"
            return "⛔ Yetkisiz işlem girişimi"
        elif action == "request":
            api = details.get("api", "")
            # Skip logging for these common requests to reduce noise
            if api.startswith("/static/"):
                return None
            if api in ["/", "/login", "/logout"]:
                return None
            if api.startswith("/api/admin/logs"):
                return None  # Don't log when viewing logs
            if api.startswith("/api/folders") and details.get("query") == "":
                return "👁️ Klasör listesi görüntülendi"
            if api.endswith("/files"):
                folder_name = api.replace("/api/", "").replace("/files", "").replace("/", " → ")
                return f"👁️ Dosyalar görüntülendi: {folder_name}"
            if api.startswith("/api/admin/"):
                admin_action = api.replace("/api/admin/", "")
                if admin_action == "users":
                    return "👥 Kullanıcı listesi görüntülendi"
                elif admin_action == "heads":
                    return "📋 Klasör listesi alındı"
                elif admin_action == "create-user":
                    return "👤 Yeni kullanıcı oluşturuldu"
                elif admin_action == "delete-user":
                    return "❌ Kullanıcı silindi"
                elif admin_action == "set-password":
                    return "🔑 Kullanıcı şifresi değiştirildi"
                elif admin_action == "set-perms":
                    return "🛡️ Kullanıcı yetkileri güncellendi"
                return f"⚙️ Yönetici işlemi: {admin_action}"
            # For file access
            if not api.startswith("/api/"):
                clean_api = api.strip("/").replace("/", " → ")
                return f"📄 Dosya açıldı: {clean_api}"
            return f"🌐 Sayfa ziyaret edildi: {api}"
        else:
            # Fallback for unknown actions
            return f"❓ Bilinmeyen işlem: {action}"

    def _get_action_category(self, action: str) -> str:
        """Get category for the action"""
        categories = {
            "login": "Güvenlik",
            "logout": "Güvenlik",
            "upload": "Dosya İşlemleri",
            "upload_chunk_done": "Dosya İşlemleri",
            "delete": "Dosya İşlemleri",
            "rename": "Dosya İşlemleri",
            "move": "Dosya İşlemleri",
            "copy": "Dosya İşlemleri",
            "create_folder": "Dosya İşlemleri",
            "unauthorized": "Güvenlik",
            "request": "Sistem Erişimi",
        }
        return categories.get(action, "Diğer")

    def log(self, user: str, ip: str, action: str, details: Dict | None = None, status: int | None = None, method: str | None = None, path: str | None = None) -> None:
        details = details or {}
        
        # Format human-readable description
        description = self._format_action_description(action, details)
        
        # Skip logging if description is None (for filtered actions)
        if description is None:
            return
        
        # Format timestamp in Turkish locale
        timestamp = datetime.now()
        turkish_time = timestamp.strftime("%d.%m.%Y %H:%M:%S")
        turkish_date = timestamp.strftime("%d %B %Y")
        turkish_hour = timestamp.strftime("%H:%M:%S")
        
        # Get day of week in Turkish
        days_tr = ["Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma", "Cumartesi", "Pazar"]
        day_of_week = days_tr[timestamp.weekday()]
        
        # Get month name in Turkish
        months_tr = ["", "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
                    "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"]
        month_name = months_tr[timestamp.month]
        readable_date = f"{timestamp.day} {month_name} {timestamp.year}, {day_of_week}"
        
        entry = {
            "ts": timestamp.isoformat(),
            "time_tr": turkish_time,
            "date_tr": readable_date,
            "time_only": turkish_hour,
            "user": user or "Anonim",
            "user_display": user or "Bilinmeyen Kullanıcı",
            "ip": ip or "-",
            "action": action,
            "category": self._get_action_category(action),
            "description": description,
            "method": method,
            "path": path,
            "status": status,
            "status_text": self._get_status_text(status),
            "details": details,
        }
        
        self.write(entry)

    def _get_status_text(self, status: int | None) -> str:
        """Convert HTTP status code to Turkish description"""
        if not status:
            return ""
        if 200 <= status < 300:
            return "Başarılı"
        elif status == 400:
            return "Hatalı İstek"
        elif status == 401:
            return "Yetkisiz"
        elif status == 403:
            return "Yasak"
        elif status == 404:
            return "Bulunamadı"
        elif 400 <= status < 500:
            return "İstemci Hatası"
        elif 500 <= status < 600:
            return "Sunucu Hatası"
        else:
            return str(status)

    def read_paginated(self, page: int, size: int) -> Tuple[int, List[Dict]]:
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return 0, []
        total = len(lines)
        end_idx = total - (page - 1) * size
        start_idx = max(0, end_idx - size)
        page_lines = lines[start_idx:end_idx] if end_idx > 0 else []
        entries: List[Dict] = []
        for ln in reversed(page_lines):
            try:
                entries.append(json.loads(ln))
            except Exception:
                continue
        return total, entries


