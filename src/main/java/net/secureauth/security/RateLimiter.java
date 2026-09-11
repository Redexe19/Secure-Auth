package net.secureauth.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe token-bucket rate limiter keyed by arbitrary strings (typically
 * IP addresses). Refills continuously at {@code permitsPerSecond} up to the
 * burst size.
 */
public final class RateLimiter {

	private final double permitsPerSecond;
	private final int burst;
	private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
	private final Clock clock;

	/** Injectable clock for tests. */
	public interface Clock {
		long nowMillis();
	}

	public RateLimiter(int permitsPerMinute, int burst) {
		this(permitsPerMinute, burst, System::currentTimeMillis);
	}

	public RateLimiter(int permitsPerMinute, int burst, Clock clock) {
		this.permitsPerSecond = Math.max(0.001, permitsPerMinute / 60.0);
		this.burst = Math.max(1, burst);
		this.clock = clock;
	}

	/** Consumes one permit for {@code key}; false means the action is rate limited. */
	public boolean tryAcquire(String key) {
		if (key == null) {
			key = "unknown";
		}
		Bucket bucket = buckets.computeIfAbsent(key, k -> new Bucket());
		synchronized (bucket) {
			long now = clock.nowMillis();
			double elapsedSeconds = (now - bucket.lastRefill) / 1000.0;
			if (elapsedSeconds > 0) {
				bucket.tokens = Math.min(burst, bucket.tokens + elapsedSeconds * permitsPerSecond);
				bucket.lastRefill = now;
			}
			if (bucket.tokens >= 1.0) {
				bucket.tokens -= 1.0;
				return true;
			}
			return false;
		}
	}

	/** Seconds until a permit becomes available for {@code key} (0 if available now). */
	public int retryInSeconds(String key) {
		if (key == null) {
			key = "unknown";
		}
		Bucket bucket = buckets.get(key);
		if (bucket == null) {
			return 0;
		}
		synchronized (bucket) {
			if (bucket.tokens >= 1.0) {
				return 0;
			}
			double deficit = 1.0 - bucket.tokens;
			return Math.max(1, (int) Math.ceil(deficit / permitsPerSecond));
		}
	}

	/** Drops buckets that have been idle for a long time to prevent memory leaks. */
	public void cleanup(long idleMillis) {
		long threshold = clock.nowMillis() - idleMillis;
		buckets.entrySet().removeIf(entry -> {
			Bucket bucket = entry.getValue();
			synchronized (bucket) {
				return bucket.lastRefill < threshold;
			}
		});
	}

	public int trackedKeys() {
		return buckets.size();
	}

	private static final class Bucket {
		double tokens;
		long lastRefill;

		Bucket() {
			this.tokens = 0;
			this.lastRefill = System.currentTimeMillis();
			// Start with one permit so the very first action is always allowed
			// (the caller decides how many initial actions are acceptable).
			this.tokens = 1.0;
		}
	}
}
