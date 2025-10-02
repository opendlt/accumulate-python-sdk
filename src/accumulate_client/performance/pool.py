"""
HTTP connection pooling for improved performance.

Provides persistent connection management with configurable limits,
timeouts, and health checking for optimal network utilization.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    aiohttp = None


logger = logging.getLogger(__name__)


class PoolError(Exception):
    """Base pool error."""
    pass


class PoolExhausted(PoolError):
    """Connection pool exhausted."""
    pass


class PoolClosed(PoolError):
    """Pool has been closed."""
    pass


@dataclass
class PoolConfig:
    """Configuration for HTTP connection pool."""
    max_connections: int = 100
    max_connections_per_host: int = 30
    connection_timeout: float = 10.0
    request_timeout: float = 30.0
    keep_alive_timeout: float = 30.0
    enable_tcp_nodelay: bool = True
    enable_compression: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0
    health_check_interval: float = 60.0
    max_idle_time: float = 300.0


@dataclass
class ConnectionStats:
    """Statistics for a connection."""
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    request_count: int = 0
    error_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def idle_time(self) -> float:
        """Get idle time in seconds."""
        return time.time() - self.last_used

    @property
    def age(self) -> float:
        """Get connection age in seconds."""
        return time.time() - self.created_at


class HttpConnectionPool:
    """
    High-performance HTTP connection pool with health monitoring.

    Features:
    - Persistent connections with configurable limits
    - Automatic health checking and stale connection cleanup
    - Per-host connection limits
    - Request timeout and retry handling
    - Connection statistics and monitoring
    """

    def __init__(self, config: PoolConfig):
        """
        Initialize connection pool.

        Args:
            config: Pool configuration

        Raises:
            ImportError: If aiohttp is not available
        """
        if not HAS_AIOHTTP:
            raise ImportError(
                "HTTP pooling requires 'aiohttp' library. "
                "Install with: pip install aiohttp"
            )

        self.config = config
        self.sessions: Dict[str, 'aiohttp.ClientSession'] = {}
        self.session_stats: Dict[str, ConnectionStats] = {}
        self.closed = False

        # Health check task
        self.health_check_task: Optional[asyncio.Task] = None

        logger.info(f"Initialized HTTP pool with max {config.max_connections} connections")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def start(self):
        """Start the connection pool."""
        if self.closed:
            raise PoolClosed("Pool has been closed")

        # Start health check task
        if self.config.health_check_interval > 0:
            self.health_check_task = asyncio.create_task(self._health_check_loop())

        logger.info("HTTP connection pool started")

    async def close(self):
        """Close all connections and cleanup resources."""
        if self.closed:
            return

        self.closed = True

        # Cancel health check task
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass

        # Close all sessions
        for host, session in self.sessions.items():
            try:
                await session.close()
                logger.debug(f"Closed session for {host}")
            except Exception as e:
                logger.warning(f"Error closing session for {host}: {e}")

        self.sessions.clear()
        self.session_stats.clear()

        logger.info("HTTP connection pool closed")

    def _get_host_key(self, url: str) -> str:
        """Extract host key from URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _get_session(self, url: str) -> 'aiohttp.ClientSession':
        """Get or create session for host."""
        if self.closed:
            raise PoolClosed("Pool has been closed")

        host_key = self._get_host_key(url)

        if host_key not in self.sessions:
            # Create new session
            connector = aiohttp.TCPConnector(
                limit=self.config.max_connections,
                limit_per_host=self.config.max_connections_per_host,
                ttl_dns_cache=300,
                use_dns_cache=True,
                enable_cleanup_closed=True,
                keepalive_timeout=self.config.keep_alive_timeout
            )

            timeout = aiohttp.ClientTimeout(
                total=self.config.request_timeout,
                connect=self.config.connection_timeout
            )

            session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                auto_decompress=self.config.enable_compression,
                trust_env=True
            )

            self.sessions[host_key] = session
            self.session_stats[host_key] = ConnectionStats()

            logger.debug(f"Created new session for {host_key}")

        return self.sessions[host_key]

    async def request(self, method: str, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """
        Make HTTP request with connection pooling.

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request arguments

        Returns:
            HTTP response

        Raises:
            PoolError: If pool operation fails
        """
        if self.closed:
            raise PoolClosed("Pool has been closed")

        host_key = self._get_host_key(url)
        session = await self._get_session(url)
        stats = self.session_stats[host_key]

        retries = 0
        last_error = None

        while retries <= self.config.max_retries:
            try:
                # Update stats
                stats.last_used = time.time()
                stats.request_count += 1

                # Make request
                response = await session.request(method, url, **kwargs)

                # Update byte stats if available
                if hasattr(response, 'content_length') and response.content_length:
                    stats.bytes_received += response.content_length

                return response

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = e
                stats.error_count += 1
                retries += 1

                if retries <= self.config.max_retries:
                    delay = self.config.retry_delay * (2 ** (retries - 1))
                    logger.warning(
                        f"Request failed (attempt {retries}/{self.config.max_retries + 1}), "
                        f"retrying in {delay}s: {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Max retries exceeded for {method} {url}: {e}")

        raise PoolError(f"Request failed after {self.config.max_retries + 1} attempts: {last_error}")

    async def get(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """Make GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """Make POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """Make PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """Make DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def _health_check_loop(self):
        """Background health check and cleanup loop."""
        while not self.closed:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._cleanup_stale_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")

    async def _cleanup_stale_connections(self):
        """Clean up stale connections."""
        current_time = time.time()
        stale_hosts = []

        for host_key, stats in self.session_stats.items():
            if stats.idle_time > self.config.max_idle_time:
                stale_hosts.append(host_key)

        for host_key in stale_hosts:
            try:
                session = self.sessions.pop(host_key, None)
                if session:
                    await session.close()
                    logger.debug(f"Cleaned up stale session for {host_key}")

                self.session_stats.pop(host_key, None)
            except Exception as e:
                logger.warning(f"Error cleaning up session for {host_key}: {e}")

        if stale_hosts:
            logger.info(f"Cleaned up {len(stale_hosts)} stale connections")

    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get pool statistics.

        Returns:
            Dictionary with pool and per-host statistics
        """
        host_stats = {}
        total_requests = 0
        total_errors = 0
        total_bytes_sent = 0
        total_bytes_received = 0

        for host_key, stats in self.session_stats.items():
            host_stats[host_key] = {
                "requests": stats.request_count,
                "errors": stats.error_count,
                "bytes_sent": stats.bytes_sent,
                "bytes_received": stats.bytes_received,
                "age_seconds": stats.age,
                "idle_seconds": stats.idle_time,
                "error_rate": stats.error_count / max(stats.request_count, 1)
            }

            total_requests += stats.request_count
            total_errors += stats.error_count
            total_bytes_sent += stats.bytes_sent
            total_bytes_received += stats.bytes_received

        return {
            "pool": {
                "total_hosts": len(self.sessions),
                "total_requests": total_requests,
                "total_errors": total_errors,
                "total_bytes_sent": total_bytes_sent,
                "total_bytes_received": total_bytes_received,
                "overall_error_rate": total_errors / max(total_requests, 1),
                "closed": self.closed
            },
            "hosts": host_stats
        }

    def get_active_connections(self) -> int:
        """Get number of active connections."""
        return len(self.sessions)

    async def warm_up(self, urls: List[str]):
        """
        Warm up connections to specified URLs.

        Args:
            urls: List of URLs to pre-connect to
        """
        logger.info(f"Warming up connections to {len(urls)} hosts")

        tasks = []
        for url in urls:
            task = asyncio.create_task(self._warmup_host(url))
            tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Connection warmup completed")

    async def _warmup_host(self, url: str):
        """Warm up connection to specific host."""
        try:
            session = await self._get_session(url)
            # Make a lightweight request to establish connection
            async with session.get(url, allow_redirects=False) as response:
                # Just establish the connection, don't care about response
                pass
        except Exception as e:
            logger.debug(f"Warmup failed for {url}: {e}")


# Factory functions for common configurations

def create_high_performance_pool() -> HttpConnectionPool:
    """Create pool optimized for high performance."""
    config = PoolConfig(
        max_connections=500,
        max_connections_per_host=100,
        connection_timeout=5.0,
        request_timeout=15.0,
        max_retries=2,
        health_check_interval=30.0
    )
    return HttpConnectionPool(config)


def create_conservative_pool() -> HttpConnectionPool:
    """Create pool with conservative settings."""
    config = PoolConfig(
        max_connections=50,
        max_connections_per_host=10,
        connection_timeout=30.0,
        request_timeout=60.0,
        max_retries=5,
        health_check_interval=120.0
    )
    return HttpConnectionPool(config)