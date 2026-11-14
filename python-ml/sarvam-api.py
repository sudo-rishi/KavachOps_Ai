import os
from pathlib import Path

from sarvamai import SarvamAI


def _get_sarvam_api_key() -> str:
    api_key = (
        os.environ.get("SARVAM_API_KEY", "").strip()
        or os.environ.get("KAVACHOPSAI_SARVAM_API_KEY", "").strip()
    )
    if api_key:
        return api_key

    env_file = Path(__file__).resolve().parents[1] / ".env"
    if env_file.is_file():
        values: dict[str, str] = {}
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, separator, value = line.partition("=")
            normalized_name = name.strip().replace(".", "_").replace("-", "_").upper()
            if separator and normalized_name in {
                "SARVAM_API_KEY",
                "KAVACHOPSAI_SARVAM_API_KEY",
            }:
                values[normalized_name] = value.strip().strip("\"'")
        return values.get("SARVAM_API_KEY") or values.get(
            "KAVACHOPSAI_SARVAM_API_KEY", ""
        )
    return ""


def main() -> None:
    api_key = _get_sarvam_api_key()
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
