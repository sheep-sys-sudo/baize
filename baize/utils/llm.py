"""Unified LLM calling utility via litellm.

Usage:
    from baize.utils.llm import call_llm
    from baize.config import BaizeConfig

    config = BaizeConfig.load()
    text = await call_llm("请生成一个 SQL 注入检测的 CodeQL 查询", config.llm.primary)

LLM interactions are logged to `.baize/llm_interactions.jsonl` (newline-delimited JSON).
Override the path with the BAIZE_LLM_LOG environment variable.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from baize.config import LLMConfig

# ── LLM interaction log ─────────────────────────────────────────────────────
# All calls to call_llm() are appended to this file as newline-delimited JSON.
# Set BAIZE_LLM_LOG to override the default path.
_LLM_LOG_PATH: Path = Path(os.environ.get("BAIZE_LLM_LOG", ".baize/llm_interactions.jsonl"))

# ── litellm model-string prefixes per provider ─────────────────────────────
# If base_url is set, we ALWAYS fall back to "openai/model" (OpenAI-compatible
# format) because virtually every Chinese provider exposes an OpenAI-compatible
# endpoint.  The prefix below is only used when NO custom base_url is given.
_LITELLM_PREFIXES: dict[str, str] = {
    "openai":      "",           # gpt-4o  (litellm treats bare names as openai)
    "anthropic":   "anthropic/", # anthropic/claude-opus-4-6
    "azure":       "azure/",     # azure/<deployment>
    "openrouter":  "openrouter/",
    "deepseek":    "deepseek/",  # litellm natively supports deepseek/*
    "dashscope":   "openai/",    # Qwen via DashScope OpenAI-compat endpoint
    "wenxin":      "wenxin/",    # ERNIE series
    "zhipu":       "zhipuai/",   # litellm supports zhipuai/*
    "moonshot":    "openai/",    # Moonshot OpenAI-compat endpoint
    "minimax":     "openai/",    # MiniMax OpenAI-compat endpoint
    "ollama":      "ollama/",    # ollama/llama3.2
}

# Default base_url for providers that need one (used when config.base_url is None)
_DEFAULT_BASE_URLS: dict[str, str] = {
    "deepseek":  "https://api.deepseek.com",
    "dashscope": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "moonshot":  "https://api.moonshot.cn/v1",
    "minimax":   "https://api.minimax.chat/v1",
    "zhipu":     "https://open.bigmodel.cn/api/paas/v4",
}


def _append_interaction_log(entry: dict) -> None:
    """Append a single LLM interaction record to the JSONL log file."""
    try:
        log_path = _LLM_LOG_PATH
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.debug(f"Could not write LLM interaction log: {exc}")


def _build_model_string(cfg: "LLMConfig") -> str:
    """Return the litellm model string for *cfg*.

    Rules:
    1. If base_url is set  → treat as OpenAI-compatible proxy → ``openai/{model}``
    2. Else if provider is openai → bare model name (litellm default)
    3. Else → ``{litellm_prefix}{model}``
    """
    if cfg.base_url:
        # Any provider with a custom base URL speaks OpenAI-compatible protocol
        return f"openai/{cfg.model}"

    prefix = _LITELLM_PREFIXES.get(cfg.provider, "")
    return f"{prefix}{cfg.model}"


def _effective_base_url(cfg: "LLMConfig") -> str | None:
    """Return the effective api_base: explicit config > provider default."""
    return cfg.base_url or _DEFAULT_BASE_URLS.get(cfg.provider)


async def call_llm(
    prompt: str,
    cfg: "LLMConfig",
    *,
    system: str | None = None,
    json_mode: bool = False,
    caller: str = "",
) -> str:
    """Call the configured LLM and return the text response.

    Args:
        prompt:    User message content.
        cfg:       LLMConfig (primary / secondary / embedding).
        system:    Optional system prompt.
        json_mode: Request JSON response format (provider must support it).
        caller:    Optional label identifying the calling component (logged).

    Returns:
        Response text (empty string on failure).
    """
    try:
        from litellm import acompletion  # type: ignore[import]
    except ImportError:
        logger.error("litellm is not installed. Run: uv add litellm")
        return ""

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    model = _build_model_string(cfg)
    api_base = _effective_base_url(cfg)

    kwargs: dict = {
        "model": model,
        "messages": messages,
        "temperature": cfg.temperature,
        "timeout": cfg.timeout,
        "num_retries": cfg.max_retries,
    }
    if cfg.api_key:
        kwargs["api_key"] = cfg.api_key
    if api_base:
        kwargs["api_base"] = api_base
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    logger.debug(f"LLM call → model={model} base_url={api_base or '(default)'}")

    t0 = time.time()
    content = ""
    error_msg = ""
    try:
        response = await acompletion(**kwargs)
        content = response.choices[0].message.content or ""
    except Exception as e:
        error_msg = str(e)
        logger.error(f"LLM call failed ({model}): {e}")
    finally:
        elapsed = round(time.time() - t0, 3)
        _append_interaction_log({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "caller": caller,
            "model": model,
            "provider": cfg.provider,
            "base_url": api_base or "",
            "json_mode": json_mode,
            "prompt_chars": len(prompt),
            "system_chars": len(system) if system else 0,
            "response_chars": len(content),
            "elapsed_s": elapsed,
            "success": bool(content),
            "error": error_msg,
            "prompt_preview": prompt[:200],
            "response_preview": content[:300],
        })

    return content


async def call_llm_with_fallback(
    prompt: str,
    primary_cfg: "LLMConfig",
    secondary_cfg: "LLMConfig | None" = None,
    *,
    system: str | None = None,
    caller: str = "",
) -> str:
    """Try primary LLM; fall back to secondary on empty/error response."""
    result = await call_llm(prompt, primary_cfg, system=system, caller=caller)
    if result:
        return result

    if secondary_cfg is not None:
        logger.info("Primary LLM returned empty; trying secondary model")
        result = await call_llm(prompt, secondary_cfg, system=system, caller=f"{caller}:fallback")

    return result
