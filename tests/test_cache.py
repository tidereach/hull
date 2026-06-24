from spektralia.cache import LRUCache


def test_cache_hit_and_miss():
    cache = LRUCache(maxsize=10)
    key = LRUCache.make_key("text", "config")
    assert cache.get(key) is None  # miss
    cache.set(key, {"result": "ok"})
    assert cache.get(key) == {"result": "ok"}  # hit


def test_lru_eviction():
    cache = LRUCache(maxsize=3)
    for i in range(4):
        key = LRUCache.make_key(f"text{i}", "config")
        cache.set(key, i)
    # First entry should be evicted
    k0 = LRUCache.make_key("text0", "config")
    assert cache.get(k0) is None


def test_invalidate_all():
    cache = LRUCache(maxsize=10)
    for i in range(5):
        key = LRUCache.make_key(f"t{i}", "c")
        cache.set(key, i)
    cache.invalidate_all()
    for i in range(5):
        key = LRUCache.make_key(f"t{i}", "c")
        assert cache.get(key) is None


def test_different_config_hash_different_key():
    k1 = LRUCache.make_key("same text", "config_a")
    k2 = LRUCache.make_key("same text", "config_b")
    assert k1 != k2


def test_stats():
    cache = LRUCache(maxsize=10)
    key = LRUCache.make_key("x", "y")
    cache.get(key)  # miss
    cache.set(key, 1)
    cache.get(key)  # hit
    s = cache.stats
    assert s["hits"] == 1
    assert s["misses"] == 1
