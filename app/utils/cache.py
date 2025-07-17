"""
Enhanced caching system with Redis and fallback support.
Fixes caching issues identified in the performance review.
"""
import pickle
import time
from collections import OrderedDict
from functools import wraps
from threading import RLock
from typing import Any, Callable, Optional, Union

import redis
import structlog
from flask import Flask

logger = structlog.get_logger()


class LRUCache:
    """Thread-safe LRU cache with TTL support for fallback when Redis unavailable."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = OrderedDict()
        self.timestamps = {}
        self.lock = RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache with TTL check."""
        with self.lock:
            if key in self.cache:
                # Check TTL
                if time.time() - self.timestamps[key] > self.default_ttl:
                    del self.cache[key]
                    del self.timestamps[key]
                    return None
                
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return self.cache[key]
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with optional TTL."""
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            else:
                if len(self.cache) >= self.max_size:
                    # Remove oldest item
                    oldest_key = next(iter(self.cache))
                    del self.cache[oldest_key]
                    del self.timestamps[oldest_key]
            
            self.cache[key] = value
            self.timestamps[key] = time.time()
    
    def delete(self, key: str) -> None:
        """Delete key from cache."""
        with self.lock:
            self.cache.pop(key, None)
            self.timestamps.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()


class CacheManager:
    """Enhanced cache manager with Redis primary and LRU fallback."""
    
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self.fallback_cache = LRUCache()
        self.key_prefix = "cookiebot:"
        self.redis_available = False
    
    def init_app(self, app: Flask) -> None:
        """Initialize cache manager with Flask app."""
        redis_url = app.config.get('REDIS_URL')
        
        if redis_url:
            try:
                self.redis_client = redis.Redis.from_url(
                    redis_url,
                    decode_responses=False,  # We'll handle encoding ourselves
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                
                # Test connection
                self.redis_client.ping()
                self.redis_available = True
                logger.info("Redis cache initialized successfully")
                
            except Exception as e:
                logger.warning("Redis unavailable, using fallback cache", error=str(e))
                self.redis_available = False
        else:
            logger.info("No Redis URL configured, using fallback cache")
    
    def _make_key(self, key: str) -> str:
        """Create prefixed cache key."""
        return f"{self.key_prefix}{key}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        cache_key = self._make_key(key)
        
        if self.redis_available and self.redis_client:
            try:
                data = self.redis_client.get(cache_key)
                if data:
                    return pickle.loads(data)
                return None
            except Exception as e:
                logger.warning("Redis get failed, falling back to LRU", error=str(e))
                self.redis_available = False
        
        # Fallback to LRU cache
        return self.fallback_cache.get(cache_key)
    
    def set(self, key: str, value: Any, ttl: int = 300) -> None:
        """Set value in cache with TTL."""
        cache_key = self._make_key(key)
        
        if self.redis_available and self.redis_client:
            try:
                serialized_value = pickle.dumps(value)
                self.redis_client.setex(cache_key, ttl, serialized_value)
                return
            except Exception as e:
                logger.warning("Redis set failed, falling back to LRU", error=str(e))
                self.redis_available = False
        
        # Fallback to LRU cache
        self.fallback_cache.set(cache_key, value, ttl)
    
    def delete(self, key: str) -> None:
        """Delete key from cache."""
        cache_key = self._make_key(key)
        
        if self.redis_available and self.redis_client:
            try:
                self.redis_client.delete(cache_key)
            except Exception as e:
                logger.warning("Redis delete failed", error=str(e))
        
        # Also delete from fallback cache
        self.fallback_cache.delete(cache_key)
    
    def delete_pattern(self, pattern: str) -> None:
        """Delete keys matching pattern."""
        cache_pattern = self._make_key(pattern)
        
        if self.redis_available and self.redis_client:
            try:
                keys = self.redis_client.keys(cache_pattern)
                if keys:
                    self.redis_client.delete(*keys)
            except Exception as e:
                logger.warning("Redis pattern delete failed", error=str(e))
        
        # For fallback cache, we'd need to iterate through all keys
        # This is expensive, so we'll just clear the entire cache
        if not self.redis_available:
            self.fallback_cache.clear()
    
    def clear(self) -> None:
        """Clear all cache entries."""
        if self.redis_available and self.redis_client:
            try:
                pattern = self._make_key("*")
                keys = self.redis_client.keys(pattern)
                if keys:
                    self.redis_client.delete(*keys)
            except Exception as e:
                logger.warning("Redis clear failed", error=str(e))
        
        self.fallback_cache.clear()


# Global cache manager instance
cache_manager = CacheManager()


def cached(ttl: int = 300, key_func: Optional[Callable] = None):
    """
    Decorator for caching function results.
    
    Args:
        ttl: Time to live in seconds
        key_func: Function to generate cache key from args/kwargs
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Create key from function name and arguments
                key_parts = [f.__name__]
                if args:
                    key_parts.extend(str(arg) for arg in args)
                if kwargs:
                    key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
                cache_key = ":".join(key_parts)
            
            # Try to get from cache
            result = cache_manager.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = f(*args, **kwargs)
            cache_manager.set(cache_key, result, ttl)
            return result
        
        # Add cache management methods to the decorated function
        wrapper.cache_key = lambda *args, **kwargs: (
            key_func(*args, **kwargs) if key_func 
            else f"{f.__name__}:{':'.join(str(arg) for arg in args)}"
        )
        wrapper.invalidate = lambda *args, **kwargs: cache_manager.delete(
            wrapper.cache_key(*args, **kwargs)
        )
        
        return wrapper
    return decorator


def invalidate_user_cache(user_id: int) -> None:
    """Invalidate all cache entries for a specific user."""
    patterns = [
        f"dashboard_summary:{user_id}",
        f"user_websites:{user_id}",
        f"website_metrics:{user_id}:*",
        f"website_analytics:{user_id}:*"
    ]
    
    for pattern in patterns:
        cache_manager.delete_pattern(pattern)


def invalidate_website_cache(user_id: int, website_id: int) -> None:
    """Invalidate cache entries for a specific website."""
    patterns = [
        f"website_metrics:{user_id}:{website_id}",
        f"website_analytics:{user_id}:{website_id}:*",
        f"dashboard_summary:{user_id}",
        f"user_websites:{user_id}"
    ]
    
    for pattern in patterns:
        cache_manager.delete_pattern(pattern)


# Specific cache key generators for common use cases
def dashboard_cache_key(user_id: int) -> str:
    """Generate cache key for dashboard data."""
    return f"dashboard_summary:{user_id}"


def website_metrics_cache_key(user_id: int, website_id: int) -> str:
    """Generate cache key for website metrics."""
    return f"website_metrics:{user_id}:{website_id}"


def analytics_cache_key(user_id: int, website_id: int, start_date: str, end_date: str) -> str:
    """Generate cache key for analytics data."""
    return f"website_analytics:{user_id}:{website_id}:{start_date}:{end_date}"

