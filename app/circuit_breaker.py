import logging
import time
from enum import Enum

from app.config import settings
from app.metrics import ollama_circuit_state

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Simple circuit breaker for Ollama calls.

    - CLOSED: requests flow normally.
    - After ``failure_threshold`` consecutive failures the circuit opens.
    - OPEN: all requests are rejected immediately for ``cooldown_seconds``.
    - After the cooldown, the circuit moves to HALF_OPEN and allows one probe request.
    - If the probe succeeds the circuit closes; if it fails the circuit re-opens.
    """

    def __init__(
        self,
        failure_threshold: int | None = None,
        cooldown_seconds: int | None = None,
    ):
        self.failure_threshold = (
            failure_threshold
            if failure_threshold is not None
            else settings.circuit_breaker_failure_threshold
        )
        self.cooldown_seconds = (
            cooldown_seconds
            if cooldown_seconds is not None
            else settings.circuit_breaker_cooldown_seconds
        )
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._opened_at: float = 0.0
        self._update_gauge()

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._opened_at >= self.cooldown_seconds:
                self._state = CircuitState.HALF_OPEN
                self._update_gauge()
                logger.info("Circuit breaker transitioned to HALF_OPEN (cooldown elapsed)")
        return self._state

    @property
    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN

    def record_success(self) -> None:
        if self._state in (CircuitState.HALF_OPEN, CircuitState.CLOSED):
            self._failure_count = 0
            self._state = CircuitState.CLOSED
            self._update_gauge()

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._state == CircuitState.HALF_OPEN:
            self._open()
            logger.warning("Circuit breaker re-opened after HALF_OPEN probe failure")
        elif self._failure_count >= self.failure_threshold:
            self._open()
            logger.warning(
                "Circuit breaker OPEN after %d consecutive failures", self._failure_count
            )

    def _open(self) -> None:
        self._state = CircuitState.OPEN
        self._opened_at = time.monotonic()
        self._update_gauge()

    def _update_gauge(self) -> None:
        gauge_value = {
            CircuitState.CLOSED: 0,
            CircuitState.OPEN: 1,
            CircuitState.HALF_OPEN: 2,
        }
        ollama_circuit_state.set(gauge_value[self._state])
