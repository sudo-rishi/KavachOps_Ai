import os

from sarvamai import SarvamAI


def main() -> None:
    api_key = (
        os.environ.get("SARVAM_API_KEY", "").strip()
        or os.environ.get("KAVACHOPSAI_SARVAM_API_KEY", "").strip()
    )
    if not api_key:
        raise SystemExit("Set SARVAM_API_KEY or KAVACHOPSAI_SARVAM_API_KEY")

    client = SarvamAI(api_subscription_key=api_key)
    response = client.chat.completions_v2(
        model=os.environ.get("SARVAM_MODEL", "glm5.3"),
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
