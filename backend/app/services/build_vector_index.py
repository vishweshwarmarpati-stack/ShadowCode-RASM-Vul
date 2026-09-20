import json
import pickle
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer


KNOWLEDGE_PATH = Path(
    "data/rag/vulnerability_knowledge.json"
)

INDEX_PATH = Path(
    "data/rag/vulnerability.index"
)

METADATA_PATH = Path(
    "data/rag/vulnerability_metadata.pkl"
)

MODEL_NAME = (
    "sentence-transformers/all-MiniLM-L6-v2"
)


def build_vector_index():

    print("Loading vulnerability knowledge...")

    with open(
        KNOWLEDGE_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        knowledge = json.load(file)

    print(
        f"Loaded {len(knowledge)} records."
    )

    codes = []
    metadata = []

    for item in knowledge:

        code = item.get(
            "code",
            ""
        )

        if not code.strip():
            continue

        codes.append(code)
        metadata.append(item)

    print(
        f"Valid code samples: {len(codes)}"
    )

    print()
    print(
        "Loading embedding model..."
    )

    model = SentenceTransformer(
        MODEL_NAME
    )

    print()
    print(
        "Generating code embeddings..."
    )

    embeddings = model.encode(
        codes,
        show_progress_bar=True,
        normalize_embeddings=True,
        convert_to_numpy=True
    )

    print(
        "Embedding shape:",
        embeddings.shape
    )

    dimension = embeddings.shape[1]

    index = faiss.IndexFlatIP(
        dimension
    )

    index.add(
        embeddings
    )

    INDEX_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    faiss.write_index(
        index,
        str(INDEX_PATH)
    )

    with open(
        METADATA_PATH,
        "wb"
    ) as file:

        pickle.dump(
            metadata,
            file
        )

    print()
    print(
        "======================================"
    )
    print(
        "CODE VECTOR INDEX CREATED"
    )
    print(
        "======================================"
    )

    print(
        "Records:",
        len(metadata)
    )

    print(
        "Vectors:",
        index.ntotal
    )

    print(
        "Dimension:",
        dimension
    )

    print(
        "Index:",
        INDEX_PATH
    )

    print(
        "Metadata:",
        METADATA_PATH
    )

    print(
        "======================================"
    )


if __name__ == "__main__":

    build_vector_index()