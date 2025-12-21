"""
Rate Limiter Module

Implements rate limiting for WAF using sliding window algorithm
"""

import time
from collections import defaultdict, deque
from threading import Lock
from waf_config import waf_config
from constants import (
    WINDOW_1_MINUTE,
    WINDOW_10_SECONDS,
    WINDOW_5_MINUTES,
    RATE_LIMITER_IP_WINDOW,
    RATE_LIMITER_GLOBAL_WINDOW,
    RATE_LIMITER_PATH_WINDOW,
    CLEANUP_INTERVAL,
    DEFAULT_PER_IP_LIMIT,
    DEFAULT_GLOBAL_LIMIT,
    DEFAULT_BURST_LIMIT
)


class RateLimiter:
    """Rate limiter using sliding window algorithm"""

    def __init__(self):
        """Initialize rate limiter"""
        self.config = waf_config

        # Per-IP tracking: {ip: deque([timestamp1, timestamp2, ...])}
        self.ip_windows = defaultdict(lambda: deque(maxlen=RATE_LIMITER_IP_WINDOW))

        # Global tracking: deque([timestamp1, timestamp2, ...])
        self.global_window = deque(maxlen=RATE_LIMITER_GLOBAL_WINDOW)

        # Per-IP per-path tracking: {(ip, path): deque([...])}
        self.ip_path_windows = defaultdict(lambda: deque(maxlen=RATE_LIMITER_PATH_WINDOW))

        # Thread safety
        self.lock = Lock()

        # Cleanup interval
        self.last_cleanup = time.time()
        self.cleanup_interval = CLEANUP_INTERVAL

    def check_rate_limit(self, ip, path=None):
        """
        Check if request is within rate limits

        Args:
            ip: Client IP address
            path: Request path (optional)

        Returns:
            tuple: (allowed: bool, retry_after: int, info: dict)
        """
        if not self.config.is_rate_limiting_enabled():
            return True, 0, {'rate_limiting': 'disabled'}

        current_time = time.time()

        with self.lock:
            # Periodic cleanup
            if current_time - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_entries(current_time)
                self.last_cleanup = current_time

            # Check global rate limit
            global_limit = self.config.get('rate_limit_global', DEFAULT_GLOBAL_LIMIT)
            global_requests = self._count_requests_in_window(
                self.global_window,
                current_time,
                WINDOW_1_MINUTE
            )

            if global_requests >= global_limit:
                retry_after = self._calculate_retry_after(self.global_window, WINDOW_1_MINUTE)
                return False, retry_after, {
                    'reason': 'global_rate_limit',
                    'limit': global_limit,
                    'current': global_requests,
                    'window': '1 minute'
                }

            # Check per-IP rate limit
            per_ip_limit = self.config.get_rate_limit(path)
            ip_requests = self._count_requests_in_window(
                self.ip_windows[ip],
                current_time,
                60  # 1 minute window
            )

            if ip_requests >= per_ip_limit:
                retry_after = self._calculate_retry_after(self.ip_windows[ip], 60)
                return False, retry_after, {
                    'reason': 'per_ip_rate_limit',
                    'limit': per_ip_limit,
                    'current': ip_requests,
                    'window': '1 minute',
                    'ip': ip
                }

            # Check burst limit
            burst_limit = self.config.get('rate_limit_burst', 20)
            burst_requests = self._count_requests_in_window(
                self.ip_windows[ip],
                current_time,
                10  # 10 second window for burst
            )

            if burst_requests >= burst_limit:
                retry_after = self._calculate_retry_after(self.ip_windows[ip], 10)
                return False, retry_after, {
                    'reason': 'burst_rate_limit',
                    'limit': burst_limit,
                    'current': burst_requests,
                    'window': '10 seconds',
                    'ip': ip
                }

            # Check path-specific limit (if configured)
            if path:
                key = (ip, path)
                path_limit = self.config.get_rate_limit(path)

                # Only check if path has specific limit different from default
                default_limit = self.config.get('rate_limit_per_ip', 100)
                if path_limit != default_limit:
                    path_requests = self._count_requests_in_window(
                        self.ip_path_windows[key],
                        current_time,
                        60
                    )

                    if path_requests >= path_limit:
                        retry_after = self._calculate_retry_after(self.ip_path_windows[key], 60)
                        return False, retry_after, {
                            'reason': 'path_rate_limit',
                            'limit': path_limit,
                            'current': path_requests,
                            'window': '1 minute',
                            'ip': ip,
                            'path': path
                        }

            # All checks passed
            return True, 0, {
                'per_ip_remaining': per_ip_limit - ip_requests,
                'global_remaining': global_limit - global_requests
            }

    def record_request(self, ip, path=None):
        """
        Record a request for rate limiting

        Args:
            ip: Client IP address
            path: Request path (optional)
        """
        if not self.config.is_rate_limiting_enabled():
            return

        current_time = time.time()

        with self.lock:
            # Record in IP window
            self.ip_windows[ip].append(current_time)

            # Record in global window
            self.global_window.append(current_time)

            # Record in path-specific window if path provided
            if path:
                key = (ip, path)
                self.ip_path_windows[key].append(current_time)

    def _count_requests_in_window(self, window, current_time, window_seconds):
        """
        Count requests within time window

        Args:
            window: Deque of timestamps
            current_time: Current timestamp
            window_seconds: Window size in seconds

        Returns:
            int: Number of requests in window
        """
        cutoff_time = current_time - window_seconds
        return sum(1 for timestamp in window if timestamp > cutoff_time)

    def _calculate_retry_after(self, window, window_seconds):
        """
        Calculate retry-after time in seconds

        Args:
            window: Deque of timestamps
            window_seconds: Window size in seconds

        Returns:
            int: Seconds to wait before retrying
        """
        if not window:
            return window_seconds

        # Find oldest request in window
        current_time = time.time()
        cutoff_time = current_time - window_seconds

        # Find first request that's still in the window
        for timestamp in window:
            if timestamp > cutoff_time:
                # This is the oldest request in current window
                # Calculate when it will expire
                expires_at = timestamp + window_seconds
                retry_after = int(expires_at - current_time)
                return max(1, retry_after)  # At least 1 second

        return window_seconds

    def _cleanup_old_entries(self, current_time):
        """
        Clean up old entries (older than 5 minutes).

        OPTIMIZATION: Uses lazy cleanup - deques automatically drop old entries
        when maxlen is reached. This method only removes empty windows from
        dictionaries to free memory.

        Args:
            current_time: Current timestamp
        """
        cutoff_time = current_time - WINDOW_5_MINUTES

        # Cleanup IP windows - only remove empty ones
        # Old timestamps naturally drop off due to maxlen
        self._cleanup_window_dict(self.ip_windows, cutoff_time)

        # Cleanup global window - trim old entries if needed
        while self.global_window and self.global_window[0] < cutoff_time:
            self.global_window.popleft()

        # Cleanup path-specific windows - only remove empty ones
        self._cleanup_window_dict(self.ip_path_windows, cutoff_time)

    def _cleanup_window_dict(self, window_dict, cutoff_time):
        """
        Helper to clean up old entries from a window dictionary.

        Args:
            window_dict: Dictionary of windows to clean
            cutoff_time: Timestamp threshold for removal
        """
        empty_keys = [key for key, window in window_dict.items()
                      if not window or window[-1] < cutoff_time]
        for key in empty_keys:
            del window_dict[key]

    def get_statistics(self):
        """Get rate limiter statistics"""
        with self.lock:
            current_time = time.time()

            # Count active IPs (with requests in last minute)
            active_ips = 0
            for ip, window in self.ip_windows.items():
                if self._count_requests_in_window(window, current_time, 60) > 0:
                    active_ips += 1

            # Global requests in last minute
            global_requests_last_minute = self._count_requests_in_window(
                self.global_window,
                current_time,
                60
            )

            return {
                'enabled': self.config.is_rate_limiting_enabled(),
                'active_ips': active_ips,
                'tracked_ips': len(self.ip_windows),
                'global_requests_last_minute': global_requests_last_minute,
                'per_ip_limit': self.config.get('rate_limit_per_ip', 100),
                'global_limit': self.config.get('rate_limit_global', 1000),
                'burst_limit': self.config.get('rate_limit_burst', 20)
            }

    def reset(self):
        """Reset all rate limit tracking"""
        with self.lock:
            self.ip_windows.clear()
            self.global_window.clear()
            self.ip_path_windows.clear()
            print("[Rate Limiter] All tracking data cleared")


# Global rate limiter instance
rate_limiter = RateLimiter()
