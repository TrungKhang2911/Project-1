from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import Settings


API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


def extract_response_text(response_body: Any) -> str:
    if not isinstance(response_body, dict):
        raise ValueError("Gemini response is not a JSON object.")

    candidates = response_body.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError(
            "Gemini returned no response candidate. Check the prompt and provider response."
        )

    text_parts: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        content = candidate.get("content")
        if not isinstance(content, dict):
            continue
        parts = content.get("parts")
        if not isinstance(parts, list):
            continue
        for part in parts:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                text_parts.append(part["text"])

    if not text_parts:
        raise ValueError(
            "Gemini response contained no text. It may have been blocked by safety filters."
        )
    return "\n".join(text_parts)


async def send_prompt(prompt: str, settings: Settings) -> str:
    api_key = settings.LLM_API_KEY
    if api_key is None or not api_key.get_secret_value().strip():
        raise RuntimeError(
            "LLM_API_KEY is missing. Set it in backend/.env and restart this script."
        )

    model_name = settings.LLM_MODEL_NAME.strip()
    if not model_name:
        raise RuntimeError("LLM_MODEL_NAME is empty in backend/.env.")

    url = f"{API_BASE_URL}/{quote(model_name, safe='')}:generateContent"
    async with httpx.AsyncClient(timeout=45.0) as client:
        response = await client.post(
            url,
            headers={"x-goog-api-key": api_key.get_secret_value()},
            json={
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2},
            },
        )

    if response.is_error:
        detail = response.text.replace(api_key.get_secret_value(), "[REDACTED]")
        raise RuntimeError(
            f"Gemini returned HTTP {response.status_code}:\n{detail}"
        )

    try:
        response_body = response.json()
    except ValueError as exc:
        raise RuntimeError("Gemini returned a response that was not valid JSON.") from exc
    return extract_response_text(response_body)


async def main() -> int:
    settings = Settings()
    prompt = input("Enter a prompt for Gemini: ").strip()
    if not prompt:
        print("Prompt must not be empty.", file=sys.stderr)
        return 2

    print(f"Sending prompt to {settings.LLM_MODEL_NAME}...")
    try:
        answer = await send_prompt(prompt, settings)
    except (httpx.TimeoutException, httpx.HTTPError) as exc:
        print(f"Gemini request failed: {type(exc).__name__}.", file=sys.stderr)
        return 1
    except (RuntimeError, ValueError) as exc:
        print(f"Gemini test failed: {exc}", file=sys.stderr)
        return 1

    print("\nGemini response:\n")
    print(answer)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
