import os
from pathlib import Path

from sarvamai import SarvamAI


def main() -> None:
    api_key = os.environ.get("SARVAM_API_KEY", "").strip()
    if not api_key:
        env_file = Path(__file__).resolve().parents[1] / ".env"
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                name, separator, value = line.partition("=")
                if separator and name.strip() == "SARVAM_API_KEY":
                    api_key = value.strip().strip("\"'")
                    break
    if not api_key:
        raise SystemExit("Set SARVAM_API_KEY in the environment or project .env file")

    client = SarvamAI(api_subscription_key=api_key)
    response = client.chat.completions_v2(
        model="glm5.3",
        messages=[
            {
                "role": "user",
                "content": "Summarise the causes of the 2008 financial crisis.",
            }
        ],
        max_tokens=4000,
    )

    print(response.choices[0].message.content)


if __name__ == "__main__":
    main()
