import json
import pickle
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer

from app.services.ast_service import ASTService


KNOWLEDGE_PATH = Path(
    "data/rag/vulnerability_knowledge.json"
)

C_INDEX_PATH = Path(
    "data/rag/ast_c.index"
)

C_METADATA_PATH = Path(
    "data/rag/ast_c_metadata.pkl"
)

CPP_INDEX_PATH = Path(
    "data/rag/ast_cpp.index"
)

CPP_METADATA_PATH = Path(
    "data/rag/ast_cpp_metadata.pkl"
)

MODEL_NAME = (
    "sentence-transformers/all-MiniLM-L6-v2"
)


def looks_like_cpp(code: str) -> bool:

    cpp_indicators = [
        "std::",
        "using namespace std",
        "#include <iostream>",
        "#include <vector>",
        "#include <string>",
        "#include <map>",
        "#include <set>",
        "#include <unordered_map>",
        "#include <unordered_set>",
        "class ",
        "template<",
        "template <",
        "public:",
        "private:",
        "protected:",
        "namespace ",
        "nullptr",
        "constexpr",
        "const_cast<",
        "static_cast<",
        "dynamic_cast<",
        "reinterpret_cast<"
    ]

    return any(
        indicator in code
        for indicator in cpp_indicators
    )


def build_ast_index():

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

    c_ast_texts = []
    c_metadata = []

    cpp_ast_texts = []
    cpp_metadata = []

    print()
    print(
        "Initializing C and C++ AST parsers..."
    )

    c_parser = ASTService(
        language="c"
    )

    cpp_parser = ASTService(
        language="cpp"
    )

    print()
    print(
        "Generating language-aware AST representations..."
    )

    for item in knowledge:

        code = item.get(
            "code",
            ""
        )

        if not code.strip():
            continue

        # ======================================
        # C++ FIRST WHEN STRONG C++ INDICATORS
        # ======================================

        if looks_like_cpp(code):

            try:

                tree = cpp_parser.parse(
                    code
                )

                if (
                    tree is not None
                    and not tree.root_node.has_error
                ):

                    ast = (
                        cpp_parser.get_compact_ast(
                            code
                        )
                    )

                    if ast:

                        cpp_ast_texts.append(
                            ast
                        )

                        cpp_metadata.append(
                            item
                        )

                        continue

            except Exception:
                pass

        # ======================================
        # TRY C
        # ======================================

        try:

            tree = c_parser.parse(
                code
            )

            if (
                tree is not None
                and not tree.root_node.has_error
            ):

                ast = (
                    c_parser.get_compact_ast(
                        code
                    )
                )

                if ast:

                    c_ast_texts.append(
                        ast
                    )

                    c_metadata.append(
                        item
                    )

                    continue

        except Exception:
            pass

        # ======================================
        # FALLBACK TO C++
        # ======================================

        try:

            tree = cpp_parser.parse(
                code
            )

            if (
                tree is not None
                and not tree.root_node.has_error
            ):

                ast = (
                    cpp_parser.get_compact_ast(
                        code
                    )
                )

                if ast:

                    cpp_ast_texts.append(
                        ast
                    )

                    cpp_metadata.append(
                        item
                    )

        except Exception:
            pass

    print()
    print(
        "C AST samples   :",
        len(c_ast_texts)
    )

    print(
        "C++ AST samples :",
        len(cpp_ast_texts)
    )

    print(
        "Excluded samples:",
        len(knowledge)
        - len(c_ast_texts)
        - len(cpp_ast_texts)
    )

    if not c_ast_texts and not cpp_ast_texts:

        raise ValueError(
            "No valid AST representations found."
        )

    # ==========================================
    # LOAD EMBEDDING MODEL
    # ==========================================

    print()
    print(
        "Loading embedding model..."
    )

    model = SentenceTransformer(
        MODEL_NAME
    )

    # ==========================================
    # C INDEX
    # ==========================================

    if c_ast_texts:

        print()
        print(
            "Generating C AST embeddings..."
        )

        c_embeddings = model.encode(
            c_ast_texts,
            show_progress_bar=True,
            normalize_embeddings=True,
            convert_to_numpy=True
        )

        print(
            "C embedding shape:",
            c_embeddings.shape
        )

        c_index = faiss.IndexFlatIP(
            c_embeddings.shape[1]
        )

        c_index.add(
            c_embeddings
        )

        C_INDEX_PATH.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        faiss.write_index(
            c_index,
            str(C_INDEX_PATH)
        )

        with open(
            C_METADATA_PATH,
            "wb"
        ) as file:

            pickle.dump(
                c_metadata,
                file
            )

        print(
            "C AST index saved to:",
            C_INDEX_PATH
        )

        print(
            "C AST metadata saved to:",
            C_METADATA_PATH
        )

    # ==========================================
    # C++ INDEX
    # ==========================================

    if cpp_ast_texts:

        print()
        print(
            "Generating C++ AST embeddings..."
        )

        cpp_embeddings = model.encode(
            cpp_ast_texts,
            show_progress_bar=True,
            normalize_embeddings=True,
            convert_to_numpy=True
        )

        print(
            "C++ embedding shape:",
            cpp_embeddings.shape
        )

        cpp_index = faiss.IndexFlatIP(
            cpp_embeddings.shape[1]
        )

        cpp_index.add(
            cpp_embeddings
        )

        CPP_INDEX_PATH.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        faiss.write_index(
            cpp_index,
            str(CPP_INDEX_PATH)
        )

        with open(
            CPP_METADATA_PATH,
            "wb"
        ) as file:

            pickle.dump(
                cpp_metadata,
                file
            )

        print(
            "C++ AST index saved to:",
            CPP_INDEX_PATH
        )

        print(
            "C++ AST metadata saved to:",
            CPP_METADATA_PATH
        )

    print()
    print(
        "=========================================="
    )
    print(
        "LANGUAGE-AWARE AST INDEXES CREATED"
    )
    print(
        "=========================================="
    )

    print(
        "C records      :",
        len(c_metadata)
    )

    print(
        "C++ records    :",
        len(cpp_metadata)
    )

    print(
        "Excluded       :",
        len(knowledge)
        - len(c_metadata)
        - len(cpp_metadata)
    )

    print(
        "=========================================="
    )


if __name__ == "__main__":

    build_ast_index()