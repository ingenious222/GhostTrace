"""
core/agent.py
──────────────────────────────────────────────────────────────
MemForensicAgent — ReAct-style LLM agent that drives the
forensic investigation loop: observe → think → act (tool call)
→ observe result → loop → final answer.

Supports OpenAI (GPT-4o), Ollama (local models), and OpenRouter.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Generator

from openai import OpenAI

from core.system_prompt import get_system_prompt
from core.tool_executor import execute_tool_call
from core.tool_registry import get_tools

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ollama compatibility shim
# ---------------------------------------------------------------------------

# OpenRouter default
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct:free"

# Fallback chain — tried in order until a non-empty response is received
FREE_MODEL_FALLBACKS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "deepseek/deepseek-r1:free",
    "google/gemma-3-27b-it:free",
    "mistralai/mistral-7b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
]


def _get_client() -> OpenAI:
    """Return an OpenAI-compatible client (OpenAI, Ollama, or OpenRouter)."""
    provider = os.getenv("LLM_PROVIDER", "openrouter").lower()
    if provider == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        return OpenAI(api_key="ollama", base_url=base_url)
    if provider == "openrouter":
        api_key = os.getenv("OPENROUTER_API_KEY", "")
        base_url = os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL)
        return OpenAI(api_key=api_key, base_url=base_url)
    # fallback: standard OpenAI
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))


def _get_model() -> str:
    provider = os.getenv("LLM_PROVIDER", "openrouter").lower()
    if provider == "ollama":
        return os.getenv("OLLAMA_MODEL", "llama3")
    if provider == "openrouter":
        return os.getenv("OPENROUTER_MODEL", OPENROUTER_DEFAULT_MODEL)
    return os.getenv("LLM_MODEL", "gpt-4o")


# ---------------------------------------------------------------------------
# MemForensicAgent
# ---------------------------------------------------------------------------

class MemForensicAgent:
    """
    A ReAct agent for memory forensic investigations.

    Usage:
        agent = MemForensicAgent()
        for event in agent.stream("Analyse this dump for fileless malware"):
            print(event)

        # Or blocking:
        result = agent.run("Analyse this dump for fileless malware")
    """

    def __init__(self, max_iterations: int = 20, temperature: float = 0.1) -> None:
        self.client = _get_client()
        self.model = _get_model()
        self.max_iterations = max_iterations
        self.temperature = temperature
        self.tools = get_tools()
        self.system_prompt = get_system_prompt()
        self.conversation_history: list[dict[str, Any]] = []
        self.tool_call_log: list[dict[str, Any]] = []

    def reset(self) -> None:
        """Clear conversation history for a new investigation."""
        self.conversation_history = []
        self.tool_call_log = []

    def run(self, user_message: str) -> str:
        """
        Run the agent with a user message and return the final answer.
        Blocks until the agent produces a final answer or hits max_iterations.
        """
        final_answer = ""
        for event in self.stream(user_message):
            if event["type"] == "final_answer":
                final_answer = event["content"]
        return final_answer

    def stream(self, user_message: str) -> Generator[dict[str, Any], None, None]:
        """
        Stream agent events as a generator.
        Event types:
            {"type": "thinking",    "content": str}
            {"type": "tool_call",   "tool": str, "args": dict}
            {"type": "tool_result", "tool": str, "result": str}
            {"type": "final_answer","content": str}
            {"type": "error",       "content": str}
        """
        # Add user message to history
        self.conversation_history.append({"role": "user", "content": user_message})

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            *self.conversation_history,
        ]

        for iteration in range(self.max_iterations):
            logger.info("🔄 Agent iteration %d / %d", iteration + 1, self.max_iterations)

            try:
                max_tokens = int(os.getenv("AGENT_MAX_TOKENS", "2000"))
                response = self.client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=max_tokens,
                    messages=messages,  # type: ignore[arg-type]
                    tools=self.tools,  # type: ignore[arg-type]
                    tool_choice="auto",
                )
            except Exception as exc:  # noqa: BLE001
                error_msg = f"LLM API error: {exc}"
                logger.error(error_msg)
                yield {"type": "error", "content": error_msg}
                return

            choice = response.choices[0]
            message = choice.message

            # Emit any text content the LLM produced (chain-of-thought)
            if message.content:
                yield {"type": "thinking", "content": message.content}

            # Add assistant message to context
            messages.append(message.model_dump(exclude_unset=True))  # type: ignore[arg-type]

            # ── No tool calls → final answer ──────────────────────────────
            if not message.tool_calls or choice.finish_reason == "stop":
                content = (message.content or "").strip()
                # Empty response → rotate through fallback models
                if not content:
                    plain_msgs = [{"role": "system", "content": self.system_prompt}, {"role": "user", "content": user_message}]
                    for fallback_model in FREE_MODEL_FALLBACKS:
                        if fallback_model == self.model:
                            continue  # already tried
                        try:
                            logger.info("Trying fallback model: %s", fallback_model)
                            r2 = self.client.chat.completions.create(
                                model=fallback_model,
                                temperature=self.temperature,
                                max_tokens=max_tokens,
                                messages=plain_msgs,
                            )
                            content = (r2.choices[0].message.content or "").strip()
                            if content:
                                self.model = fallback_model  # stick with this model
                                break
                        except Exception as _fe:
                            logger.warning("Fallback model %s failed: %s", fallback_model, _fe)
                            continue
                    if not content:
                        content = "All available free models are currently under load. Please try again in a moment, or use the per-tab AI Analysis buttons."
                final_answer = content
                self.conversation_history.append({"role": "assistant", "content": final_answer})
                yield {"type": "final_answer", "content": final_answer}
                return

            # ── Execute all tool calls ────────────────────────────────────
            tool_results_msgs: list[dict[str, Any]] = []

            for tool_call in message.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                yield {"type": "tool_call", "tool": tool_name, "args": tool_args}

                result_str = execute_tool_call(tool_call)
                self.tool_call_log.append(
                    {"tool": tool_name, "args": tool_args, "result": result_str}
                )

                yield {"type": "tool_result", "tool": tool_name, "result": result_str}

                tool_results_msgs.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result_str,
                })

            messages.extend(tool_results_msgs)

        # Max iterations hit
        logger.warning("⚠️ Max iterations (%d) reached.", self.max_iterations)
        yield {
            "type": "final_answer",
            "content": (
                "⚠️ Investigation reached maximum iteration limit. "
                "Partial findings are available in the tool call log. "
                "Please run `generate_report` to compile available evidence."
            ),
        }

    def get_session_data(self) -> dict[str, Any]:
        """Return the full session data for report generation."""
        return {
            "model": self.model,
            "conversation": self.conversation_history,
            "tool_calls": self.tool_call_log,
        }
