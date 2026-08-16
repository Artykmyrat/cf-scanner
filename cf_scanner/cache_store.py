"""
cf_scanner.cache_store
========================
"Bilinen geçersiz IP" hafızası (BadIPCache).

Amaç: Bir config/mod için zaten test edilip ÇALIŞMADIĞI kanıtlanmış IP'ler
kalıcı olarak hatırlansın — program kapatılıp yeniden açılsa, tarama yarıda
kesilse bile o IP'ler BİR DAHA test edilmesin (zaman kaybı önlenir).

30 günden eski kayıtlar program her açıldığında otomatik silinir (bir IP
geçici olarak arızalı olabilir; süresiz hatırlamak yanlış sonuç verir).

Hafıza, "bağlam" (context) bazında ayrılır — örn. her config + port grubu
kendi geçersiz-IP listesine sahiptir; bir config için geçersiz olan bir IP,
başka bir config için otomatik geçersiz sayılmaz.

Dosya formatı (bad_ips.json):
{
  "<context_key>": { "<ip>": <son_test_unix_zamani>, ... },
  ...
}
"""
from __future__ import annotations

import json
import os
import time
from typing import Dict, Optional

EXPIRY_SECONDS = 30 * 24 * 3600  # 30 gün

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bad_ips.json")


class BadIPCache:
    def __init__(self, path: str = DEFAULT_PATH):
        self.path = os.path.abspath(path)
        self._data: Dict[str, Dict[str, float]] = {}
        self.load()
        self.purge_expired()

    # ------------------------------------------------------------------
    def load(self) -> None:
        if not os.path.exists(self.path):
            self._data = {}
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._data = {}

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f)
        os.replace(tmp, self.path)

    def flush(self) -> None:
        """Bellekteki bekleyen değişiklikleri diske yazar."""
        self.save()

    # ------------------------------------------------------------------
    def purge_expired(self) -> int:
        """30 günden eski kayıtları siler, silinen kayıt sayısını döner."""
        now = time.time()
        removed = 0
        for ctx in list(self._data.keys()):
            ips = self._data[ctx]
            for ip in list(ips.keys()):
                if now - ips[ip] > EXPIRY_SECONDS:
                    del ips[ip]
                    removed += 1
            if not ips:
                del self._data[ctx]
        if removed:
            self.save()
        return removed

    # ------------------------------------------------------------------
    def is_known_bad(self, context: str, ip: str) -> bool:
        return ip in self._data.get(context, {})

    def mark_bad(self, context: str, ip: str) -> None:
        self._data.setdefault(context, {})[ip] = time.time()

    def count(self, context: Optional[str] = None) -> int:
        if context is not None:
            return len(self._data.get(context, {}))
        return sum(len(v) for v in self._data.values())

    def clear(self, context: Optional[str] = None) -> int:
        if context is not None:
            n = len(self._data.get(context, {}))
            self._data.pop(context, None)
        else:
            n = self.count()
            self._data = {}
        self.save()
        return n

    def contexts(self) -> Dict[str, int]:
        """Her bağlamda kaç geçersiz IP kayıtlı olduğunu döner (gösterim için)."""
        return {ctx: len(ips) for ctx, ips in self._data.items()}
