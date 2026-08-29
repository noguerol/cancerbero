"""Example: drive Cancerbero from a custom Anthropic-compatible agent.

This script prints the Cancerbero tool catalogue in Anthropic's
``tools`` format, sends a prompt to a model, and routes every
function call the model emits through ``safe_invoke_tool``.

Requirements:

    pip install anthropic

Set the ``ANTHROPIC_API_KEY`` environment variable before running.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Add the source tree to PYTHONPATH so this example works against an
# in-tree Cancerbero checkout. In a real installation, drop the
# path manipulation and just ``import cancerbero``.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cancerbero.agentic.dispatch import install_dispatch, safe_invoke_tool
from cancerbero.agentic.schemas import tool_definitions_as_anthropic_tools


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("Set ANTHROPIC_API_KEY before running this example.")

    install_dispatch()

    # 1. Build the tool catalogue that the model will see.
    tools = tool_definitions_as_anthropic_tools()

    # 2. Send a prompt that requires Cancerbero to answer safely.
    import anthropic

    client = anthropic.Anthropic()
    prompt = (
        "I am about to recommend a model to a user. The artifact lives at"
        " ./models/qwen3-30b-q4.gguf and I have a llama.cpp build at"
        " ./vendor/llama.cpp/build/bin/llama-cli. Should I proceed? Use"
        " cancerbero_inspect to decide."
    )

    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2048,
        tools=tools,
        messages=[{"role": "user", "content": prompt}],
    )

    # 3. Route every tool_use block through safe_invoke_tool.
    messages = [{"role": "user", "content": prompt}]
    while True:
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            break

        tool_results = []
        for call in tool_uses:
            result = safe_invoke_tool(call.name, call.input)
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": call.id,
                    "content": json.dumps(result),
                }
            )
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=2048,
            tools=tools,
            messages=messages,
        )

    # 4. Print the final assistant text.
    for block in response.content:
        if block.type == "text":
            print(block.text)


if __name__ == "__main__":
    main()
