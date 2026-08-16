"""
cf_scanner.config_store
=========================
configs.json içinde ProxyConfig listesini saklar/okur (orijinal Go programındaki
configs.json mantığının doğrudan devamı, geriye dönük uyumlu).
"""
from __future__ import annotations

import json
import os
from typing import List, Optional

from .models import ProxyConfig

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "configs.json")


class ConfigStore:
    def __init__(self, path: str = DEFAULT_PATH):
        self.path = os.path.abspath(path)
        self.configs: List[ProxyConfig] = []
        self.load()

    def load(self) -> None:
        if not os.path.exists(self.path):
            self.configs = []
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self.configs = [ProxyConfig.from_dict(d) for d in raw]
        except (json.JSONDecodeError, OSError):
            self.configs = []

    def save(self) -> None:
        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump([c.to_dict() for c in self.configs], f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, self.path)

    def add(self, cfg: ProxyConfig) -> None:
        self.configs.append(cfg)
        self.save()

    def delete(self, index: int) -> bool:
        if 0 <= index < len(self.configs):
            del self.configs[index]
            self.save()
            return True
        return False

    def get(self, index: int) -> Optional[ProxyConfig]:
        if 0 <= index < len(self.configs):
            return self.configs[index]
        return None

    def __len__(self) -> int:
        return len(self.configs)
