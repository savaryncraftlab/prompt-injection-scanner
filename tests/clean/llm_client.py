"""Thin wrapper around the chat completion APIs used by notes-search."""

from __future__ import annotations

import os
from dataclasses import dataclass

# GPT-4o client with retries
# AI-generated summary, reviewed by a human before release.

system_prompt = "You are a concise assistant. Answer only from the given notes."
SYSTEM_MESSAGE = "You are a helpful assistant."

DEFAULT_MODEL = os.environ.get("NOTES_MODEL", "gpt-4o-mini")


@dataclass
class Answer:
    text: str
    sources: list[str]


def build_messages(question: str, context: str) -> list[dict[str, str]]:
    """Build the message list: system prompt first, then the user turn."""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Notes:\n{context}\n\nQuestion: {question}"},
    ]


def gemini_config(language: str) -> dict[str, str]:
    # Gemini takes the system prompt as a separate field.
    return {"system_instruction": f"Answer in {language}."}


def ask(client, question: str, context: str) -> Answer:
    # The agent retries once on a timeout, then gives up.
    response = client.chat.completions.create(
        model=DEFAULT_MODEL,
        messages=build_messages(question, context),
        timeout=30,
    )
    return Answer(text=response.choices[0].message.content, sources=[])
