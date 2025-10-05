from __future__ import annotations

import os
from typing import Any, Dict, Optional

import yaml


class YamlConfig:
    def __init__(self, path: str = "config/config.yaml") -> None:
        self._path = path
        self._data: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            self._data = {}
            return
        with open(self._path, "r", encoding="utf-8") as f:
            self._data = yaml.safe_load(f) or {}

    def get(self, *keys: str, default: Any = None) -> Any:
        data = self._data
        for key in keys:
            if not isinstance(data, dict) or key not in data:
                return default
            data = data[key]
        return data

    # Shortcuts
    def get_invite_code(self) -> Optional[str]:
        return self.get("general", "invite_code")

    def get_max_threads(self) -> int:
        return int(self.get("general", "max_threads", default=10))

    def get_start_delay_min(self) -> float:
        return float(self.get("general", "start_delay", "min", default=0.3))
    
    def get_start_delay_max(self) -> float:
        return float(self.get("general", "start_delay", "max", default=0.8))

    def get_use_proxy_for_imap(self) -> bool:
        return bool(self.get("mail", "use_proxy_for_imap", default=False))

    def get_imap_settings(self) -> Dict[str, str]:
        return dict(self.get("mail", "imap_settings", default={}))

    def get_single_imap(self) -> Optional[str]:
        use_single = self.get("mail", "use_single_imap", "enable", default=False)
        if use_single:
            return self.get("mail", "use_single_imap", "imap_server")
        return None

    # Logging
    def get_logging_level(self) -> str:
        return str(self.get("logging", "level", default="INFO")).upper()

    def get_logging_rotation(self) -> str:
        return str(self.get("logging", "rotation", default="1 day"))

    def get_logging_retention(self) -> str:
        return str(self.get("logging", "retention", default="7 days"))


_cfg: Optional[YamlConfig] = None


def get_config() -> YamlConfig:
    global _cfg
    if _cfg is None:
        _cfg = YamlConfig()
    return _cfg


