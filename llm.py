"""LLM provider abstraction.

One env var, three hosts, same graph:

    LLM_PROVIDER=groq          # default. Fast, hosted. Works in a Codespace.
    LLM_PROVIDER=ollama-cloud  # hosted Ollama. Works in a Codespace (no GPU needed).
    LLM_PROVIDER=ollama-local  # your laptop. Nothing leaves the machine.

MODEL IDs ARE PINNED HERE, IN ONE PLACE, ON PURPOSE.
Groq deprecates models on a few weeks' notice: `llama-3.3-70b-versatile` and
`llama-3.1-8b-instant` are both shut down on 2026-08-16. When that happens again,
this file is the only thing to edit.

WHY THE PROVIDERS USE DIFFERENT MODELS AND DIFFERENT CLIENTS
------------------------------------------------------------
The tidy version of this abstraction would run `gpt-oss:120b` on both Groq and
Ollama Cloud — same weights, different host, a clean A/B. It does not work. All of
the below was measured against the real Assessment schema on 2026-07-17:

  * groq / openai/gpt-oss-120b     works. Native structured output, first try.
  * ollama-cloud / gpt-oss:120b    FAILS. Same weights, different serving stack:
                                   answers in markdown prose, so the enum field
                                   never validates. Every with_structured_output
                                   method (json_schema, json_mode, function_calling)
                                   fails, via langchain-ollama AND the
                                   OpenAI-compatible endpoint.
  * ollama-cloud / gemma4:31b      works. Free tier. The default below.
  * ollama-cloud / nemotron-3-nano:30b   passes a 2-field toy schema, then returns
                                   None on the real one. A reminder that "it worked
                                   in my smoke test" is not evidence.

Two lessons worth teaching from this, both learned the hard way:

  1. "Same model" is not "same capability". Structured output is a property of the
     serving stack, not the weights. An agent that depends on it is only as
     portable as its weakest host.
  2. Test the schema you actually ship. nemotron looked fine until the schema grew
     past two fields.
"""

import os

from langchain_core.language_models.chat_models import BaseChatModel

# All verified live on 2026-07-17. Do not write model IDs from memory - they churn.
GROQ_REASON_MODEL = os.getenv("GROQ_REASON_MODEL", "openai/gpt-oss-120b")
# NOT gpt-oss:120b - see the note above. Must return schema-valid tool calls.
OLLAMA_CLOUD_MODEL = os.getenv("OLLAMA_CLOUD_MODEL", "gemma4:31b")
OLLAMA_LOCAL_MODEL = os.getenv("OLLAMA_LOCAL_MODEL", "llama3.1:8b")

OLLAMA_CLOUD_URL = "https://ollama.com/v1"  # OpenAI-compatible endpoint
OLLAMA_LOCAL_URL = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# How each host wants to be asked for structured output. Also not portable.
STRUCTURED_METHOD = {
    "groq": "function_calling",
    "ollama-cloud": "function_calling",
    "ollama-local": "function_calling",
}


def get_llm(temperature: float = 0) -> BaseChatModel:
    """Return the chat model for the configured provider."""
    provider = os.getenv("LLM_PROVIDER", "groq").lower()

    if provider == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(model=GROQ_REASON_MODEL, temperature=temperature)

    if provider == "ollama-cloud":
        # Ollama Cloud is OpenAI-compatible. Going through ChatOpenAI rather than
        # ChatOllama is what gets us usable tool calls.
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=OLLAMA_CLOUD_MODEL,
            temperature=temperature,
            base_url=OLLAMA_CLOUD_URL,
            api_key=os.environ["OLLAMA_API_KEY"],
            timeout=120,
        )

    if provider == "ollama-local":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=OLLAMA_LOCAL_MODEL,
            temperature=temperature,
            base_url=OLLAMA_LOCAL_URL,
        )

    raise ValueError(
        f"Unknown LLM_PROVIDER {provider!r}. Use groq, ollama-cloud, or ollama-local."
    )


def structured_method() -> str:
    """The with_structured_output() method this provider actually honours."""
    provider = os.getenv("LLM_PROVIDER", "groq").lower()
    return STRUCTURED_METHOD.get(provider, "function_calling")


def describe_provider() -> str:
    """Human-readable provider label for the dashboard."""
    provider = os.getenv("LLM_PROVIDER", "groq").lower()
    return {
        "groq": f"Groq / {GROQ_REASON_MODEL}",
        "ollama-cloud": f"Ollama Cloud / {OLLAMA_CLOUD_MODEL}",
        "ollama-local": f"Ollama local / {OLLAMA_LOCAL_MODEL}",
    }.get(provider, provider)
