"""Provider-agnostic LLM interface using litellm."""

from __future__ import annotations

import time

import structlog

from src.config import settings

logger = structlog.get_logger(__name__)


async def analyze(system_prompt: str, user_prompt: str) -> str:
    """Send a prompt to the configured LLM and return the response text.

    Uses litellm.acompletion() for provider-agnostic LLM calls.
    On failure, returns a fallback message rather than raising.

    Args:
        system_prompt: The system/instruction prompt.
        user_prompt: The user/data prompt.

    Returns:
        The LLM-generated text, or a fallback error message.
    """
    try:
        import litellm

        start = time.monotonic()

        response = await litellm.acompletion(
            model=settings.llm_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
            timeout=settings.llm_timeout,
            num_retries=3,
        )

        duration_ms = round((time.monotonic() - start) * 1000, 1)
        content = response.choices[0].message.content or ""

        logger.info(
            "llm_analysis_completed",
            model=settings.llm_model,
            duration_ms=duration_ms,
            input_tokens=getattr(response.usage, "prompt_tokens", None),
            output_tokens=getattr(response.usage, "completion_tokens", None),
        )

        return content

    except Exception as exc:
        logger.error("llm_analysis_failed", model=settings.llm_model, error=str(exc))
        return f"AI analysis unavailable: {exc}"
