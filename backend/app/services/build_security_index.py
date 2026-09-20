import json
import pickle
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer


KNOWLEDGE_PATH = Path(
    "data/rag/vulnerability_knowledge.json"
)

INDEX_PATH = Path(
    "data/rag/security.index"
)

METADATA_PATH = Path(
    "data/rag/security_metadata.pkl"
)

MODEL_NAME = (
    "sentence-transformers/all-MiniLM-L6-v2"
)


def build_security_index():

    print(
        "Loading vulnerability knowledge..."
    )

    with open(
        KNOWLEDGE_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        knowledge = json.load(file)

    print(
        f"Loaded {len(knowledge)} "
        f"vulnerability records."
    )

    security_texts = []
    metadata = []

    print()
    print(
        "Creating security semantic representations..."
    )

    for item in knowledge:

        code = item.get(
            "code",
            ""
        )

        if not code.strip():
            continue

        cwe = item.get(
            "cwe",
            []
        )

        message = item.get(
            "message",
            ""
        )

        vulnerable = item.get(
            "vulnerable",
            False
        )

        if isinstance(cwe, list):

            cwe_text = " ".join(
                str(value)
                for value in cwe
            )

        else:

            cwe_text = str(cwe)

        security_text = f"""
Software security vulnerability analysis.

Source code:
{code}

Vulnerable:
{vulnerable}

CWE categories:
{cwe_text}

Vulnerability information:
{message}

Security concepts:
software vulnerability
secure coding
vulnerability detection
security weakness
CWE classification
vulnerability remediation
secure source code
"""

        security_texts.append(
            security_text
        )

        metadata.append(
            item
        )

    print(
        "Valid security samples:",
        len(security_texts)
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
        "Generating security embeddings..."
    )

    embeddings = model.encode(
        security_texts,
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
        "SECURITY SEMANTIC INDEX CREATED"
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

    build_security_index()