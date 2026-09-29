import os
from google import genai

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise RuntimeError("GEMINI_API_KEY is not set")

client = genai.Client(api_key=api_key)

response = client.models.generate_content(
    model="gemini-3.5-flash",
    contents="Explain in one sentence what a network intrusion detection system does."
)

print(response.text)
