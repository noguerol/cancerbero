"""Example: drive Cancerbero from a custom OpenAI-compatible agent.

This script prints the Cancerbero tool catalogue in OpenAI's
``tools`` format, sends a prompt to a model, and routes every
function call the model emits through ``safe_invoke_tool``.

Requirements:

    pip install openai

Set the ``OPENAI_API_KEY`` environment variable before running.
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
from cancerbero.agentic.schemas import tool_definitions_as_openai_tools


def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("Set OPENAI_API_KEY before running this example.")

    install_dispatch()

    # 1. Build the tool catalogue that the model will see.
    tools = tool_definitions_as_openai_tools()

    # 2. Send a prompt that requires Cancerbero to answer safely.
    from openai import OpenAI

    client = OpenAI()
    prompt = (
        "I am about to recommend a model to a user. The artifact lives at"
        " ./models/qwen3-30b-q4.gguf and I have a llama.cpp build at"
        " ./vendor/llama.cpp/build/bin/llama-cli. Should I proceed? Use"
        " cancerbero_inspect to decide."
    )
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        tools=tools,
    )

    message = response.choices[0].message

    # 3. Route every tool call through safe_invoke_tool.
    while message.tool_calls:
        tool_messages = []
        for call in message.tool_calls:
            name = call.function.name
            arguments = json.loads(call.function.arguments or "{}")
            result = safe_invoke_tool(name, arguments)
            tool_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": json.dumps(result),
                }
            )
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "user", "content": prompt},
                message,
                *tool_messages,
            ],
            tools=tools,
        )
        message = response.choices[0].message

    # 4. Print the final assistant message.
    print(message.content)


if __name__ == "__main__":
    main()
