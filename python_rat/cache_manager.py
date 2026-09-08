"""
cache_manager.py — Incremental Analysis Cache (Plan #15)
Caches:
 - Parsed ASTs
 - Project index
 - Symbol information
 - Data-flow information

When developer changes one file, analyze only affected parts.
Implements Dataverse cache management pattern #6.
"""
from __future__ import annotations
import re
import json
import hashlib
import pathlib
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Any
from functools import lru_cache
import weakref

@dataclass
class FileCacheEntry:
    file: str
    hash: str
    mtime: float
    size: int
    ast_cached: bool = False
    taint_cached: bool = False

@dataclass
class ProjectCache:
    project_root: str
    version: str = "1.0"  # bump to invalidate
    files: Dict[str, FileCacheEntry] = field(default_factory=dict)
    last_full_scan: float = 0.0
    ast_hit_rate: float = 0.0

    def to_dict(self):
        return {"project_root": self.project_root, "version": self.version, "files": {k: asdict(v) for k, v in self.files.items()}, "last_full_scan": self.last_full_scan}

    @classmethod
    def from_dict(cls, data: Dict) -> "ProjectCache":
        pc = cls(project_root=data.get("project_root", ""), version=data.get("version", "1.0"), last_full_scan=data.get("last_full_scan", 0))
        for k, v in data.get("files", {}).items():
            pc.files[k] = FileCacheEntry(**v)
        return pc

class CacheManager:
    """
    Manages incremental cache. Uses:
    - lru_cache for hot paths
    - weakref for file content cache (Pattern 20)
    - Batch I/O
    - File hash + mtime for invalidation
    """
    def __init__(self, project_root: pathlib.Path):
        self.project_root = pathlib.Path(project_root).resolve()
        self.cache_dir = self.project_root / ".rat" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "project_cache.json"
        self.content_cache: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self._project_cache: Optional[ProjectCache] = None
        self._load()

    def _load(self):
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text())
                self._project_cache = ProjectCache.from_dict(data)
                # Validate version
                if self._project_cache.version != "1.0":
                    self.flush()
            except:
                self._project_cache = ProjectCache(project_root=str(self.project_root))
        else:
            self._project_cache = ProjectCache(project_root=str(self.project_root))

    def save(self):
        try:
            if self._project_cache:
                self.cache_file.write_text(json.dumps(self._project_cache.to_dict(), indent=2))
        except Exception:
            pass

    @lru_cache(maxsize=2048)
    def file_hash(self, file_path: str) -> str:
        p = pathlib.Path(file_path)
        if not p.is_absolute():
            p = self.project_root / file_path
        try:
            return hashlib.md5(p.read_bytes()).hexdigest()[:16]
        except:
            return "missing"

    def is_changed(self, file_path: pathlib.Path) -> bool:
        """Check if file needs re-analysis (mtime + hash)."""
        try:
            rel = str(file_path.relative_to(self.project_root))
        except ValueError:
            rel = str(file_path)
        try:
            stat = file_path.stat()
            mtime = stat.st_mtime
            size = stat.st_size
        except:
            return True
        entry = self._project_cache.files.get(rel)  # type: ignore
        if not entry:
            return True
        if entry.mtime != mtime or entry.size != size:
            # Hash check to avoid false positive on mtime touch
            current_hash = self.file_hash(rel)
            if current_hash != entry.hash:
                return True
        return False

    def mark_analyzed(self, file_path: pathlib.Path):
        try:
            rel = str(file_path.relative_to(self.project_root))
        except ValueError:
            rel = str(file_path)
        try:
            stat = file_path.stat()
            h = self.file_hash(rel)
            self._project_cache.files[rel] = FileCacheEntry(file=rel, hash=h, mtime=stat.st_mtime, size=stat.st_size, ast_cached=True, taint_cached=True)  # type: ignore
        except:
            pass

    def get_changed_files(self, all_files: List[pathlib.Path]) -> List[pathlib.Path]:
        """Return only files that changed since last scan (incremental)."""
        changed = []
        # Use batch check with generator to save memory (Pattern 19)
        for fp in all_files:
            if self.is_changed(fp):
                changed.append(fp)
        return changed

    def get_unchanged_files(self, all_files: List[pathlib.Path]) -> List[pathlib.Path]:
        changed_set = set(str(p.resolve()) for p in self.get_changed_files(all_files))
        return [p for p in all_files if str(p.resolve()) not in changed_set]

    def flush(self):
        """Flush all caches (call when metadata changes)."""
        try:
            for f in self.cache_dir.glob("*.json"):
                f.unlink()
            # Also clear AST cache
            ast_dir = self.cache_dir / "ast"
            if ast_dir.exists():
                for f in ast_dir.glob("*.json"):
                    f.unlink()
            self.file_hash.cache_clear()
            self._project_cache = ProjectCache(project_root=str(self.project_root))
            self.save()
        except Exception:
            pass

    def stats(self) -> Dict:
        if not self._project_cache:
            return {}
        total = len(self._project_cache.files)  # type: ignore
        return {"cached_files": total, "cache_dir": str(self.cache_dir), "last_scan": self._project_cache.last_full_scan}  # type: ignore

    def update_last_scan(self):
        self._project_cache.last_full_scan = time.time()  # type: ignore
        self.save()

# Global singleton per project
_cache_instances: Dict[str, CacheManager] = {}

def get_cache_manager(project_root: pathlib.Path) -> CacheManager:
    key = str(pathlib.Path(project_root).resolve())
    if key not in _cache_instances:
        _cache_instances[key] = CacheManager(pathlib.Path(project_root))
    return _cache_instances[key]
