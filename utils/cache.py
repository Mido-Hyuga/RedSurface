import json
import os
import hashlib
import time
from typing import Any, Optional
from pathlib import Path

class FileCache:
    """Simple file-based cache for API responses."""
    
    def __init__(self, cache_dir: str = ".cache", ttl: int = 86400):
        """
        Initialize the file cache.
        
        Args:
            cache_dir: Directory to store cache files
            ttl: Time to live in seconds (default: 24 hours)
        """
        self.cache_dir = Path(cache_dir)
        self.ttl = ttl
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        if not self.cache_dir.exists():
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, key: str) -> Path:
        """Generate cache file path from key."""
        hashed_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hashed_key}.json"

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found or expired
        """
        cache_path = self._get_cache_path(key)
        
        if not cache_path.exists():
            return None
            
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            # Check expiration
            if time.time() - data["timestamp"] > self.ttl:
                return None
                
            return data["value"]
        except Exception:
            return None

    def set(self, key: str, value: Any) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
        """
        cache_path = self._get_cache_path(key)
        
        data = {
            "timestamp": time.time(),
            "value": value
        }
        
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass
