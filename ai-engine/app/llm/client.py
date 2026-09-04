import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

API_KEY = os.getenv("FEATHERLESS_API_KEY")

if not API_KEY:
    raise RuntimeError("FEATHERLESS_API_KEY is not set in the .env file")

client = OpenAI(
    api_key=API_KEY,
    base_url="https://api.featherless.ai/v1",
)


def generate_security_analysis(prompt: str) -> str:
    response = client.chat.completions.create(
        model="Qwen/Qwen2.5-Coder-32B-Instruct",
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    return response.choices[0].message.content or ""