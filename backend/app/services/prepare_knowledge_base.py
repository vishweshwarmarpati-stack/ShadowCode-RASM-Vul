from datasets import load_dataset
import json
from pathlib import Path

OUTPUT_PATH = Path(
    "data/rag/vulnerability_knowledge.json"
)

MAX_RECORDS = 5000


def prepare_knowledge_base():

    print("Loading DiverseVul dataset...")

    dataset = load_dataset(
        "claudios/DiverseVul",
        split="test"
    )

    print(
        "Total records:",
        len(dataset)
    )

    knowledge = []

    for dataset_index, record in enumerate(dataset):

        code = record.get(
            "func",
            ""
        )

        target = record.get(
            "target",
            0
        )

        if not code:
            continue

        knowledge.append({
            "record_id": dataset_index,

            "code": code,

            "vulnerable": bool(target),

            "cwe": record.get(
                "cwe",
                []
            ),

            "project": record.get(
                "project",
                ""
            ),

            "commit_id": record.get(
                "commit_id",
                ""
            ),

            "message": record.get(
                "message",
                ""
            )
        })

        if len(knowledge) >= MAX_RECORDS:
            break

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            knowledge,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(
        f"Saved {len(knowledge)} records "
        f"to {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    prepare_knowledge_base()