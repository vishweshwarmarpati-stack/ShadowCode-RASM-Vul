import pickle
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer

from app.services.ast_service import ASTService


CODE_INDEX_PATH = Path(
    "data/rag/vulnerability.index"
)

CODE_METADATA_PATH = Path(
    "data/rag/vulnerability_metadata.pkl"
)

C_AST_INDEX_PATH = Path(
    "data/rag/ast_c.index"
)

C_AST_METADATA_PATH = Path(
    "data/rag/ast_c_metadata.pkl"
)

CPP_AST_INDEX_PATH = Path(
    "data/rag/ast_cpp.index"
)

CPP_AST_METADATA_PATH = Path(
    "data/rag/ast_cpp_metadata.pkl"
)

SECURITY_INDEX_PATH = Path(
    "data/rag/security.index"
)

SECURITY_METADATA_PATH = Path(
    "data/rag/security_metadata.pkl"
)

MODEL_NAME = (
    "sentence-transformers/all-MiniLM-L6-v2"
)


# ==================================================
# VIEW WEIGHTS
# ==================================================

CODE_WEIGHT = 0.45
AST_WEIGHT = 0.30
SECURITY_WEIGHT = 0.25


# ==================================================
# EXTRA BONUSES
# ==================================================

SECURITY_BOOST_WEIGHT = 0.10

# Stronger than before so that explicit CWE
# agreement has meaningful influence.
CWE_RELEVANCE_BONUS = 0.15

# Small additional bonus when more than one
# relevant CWE matches.
CWE_MULTI_MATCH_BONUS = 0.05

AGREEMENT_BONUS = 0.10


# ==================================================
# INTERNAL RETRIEVAL POOL
# ==================================================

RETRIEVAL_POOL_SIZE = 20


class MultiViewRetriever:

    def __init__(self):

        print(
            "Loading multi-view retrieval indexes..."
        )

        # ==========================================
        # EMBEDDING MODEL
        # ==========================================

        self.model = SentenceTransformer(
            MODEL_NAME
        )

        # ==========================================
        # CODE INDEX
        # ==========================================

        self.code_index = faiss.read_index(
            str(CODE_INDEX_PATH)
        )

        with open(
            CODE_METADATA_PATH,
            "rb"
        ) as file:

            self.code_metadata = pickle.load(
                file
            )

        # ==========================================
        # C AST INDEX
        # ==========================================

        self.c_ast_index = faiss.read_index(
            str(C_AST_INDEX_PATH)
        )

        with open(
            C_AST_METADATA_PATH,
            "rb"
        ) as file:

            self.c_ast_metadata = pickle.load(
                file
            )

        # ==========================================
        # C++ AST INDEX
        # ==========================================

        self.cpp_ast_index = faiss.read_index(
            str(CPP_AST_INDEX_PATH)
        )

        with open(
            CPP_AST_METADATA_PATH,
            "rb"
        ) as file:

            self.cpp_ast_metadata = pickle.load(
                file
            )

        # ==========================================
        # SECURITY INDEX
        # ==========================================

        self.security_index = faiss.read_index(
            str(SECURITY_INDEX_PATH)
        )

        with open(
            SECURITY_METADATA_PATH,
            "rb"
        ) as file:

            self.security_metadata = pickle.load(
                file
            )

        # ==========================================
        # AST SERVICES
        # ==========================================

        self.c_ast_service = ASTService(
            language="c"
        )

        self.cpp_ast_service = ASTService(
            language="cpp"
        )

        # ==========================================
        # INDEX INFORMATION
        # ==========================================

        print(
            "Code vectors:",
            self.code_index.ntotal
        )

        print(
            "C AST vectors:",
            self.c_ast_index.ntotal
        )

        print(
            "C++ AST vectors:",
            self.cpp_ast_index.ntotal
        )

        print(
            "Security vectors:",
            self.security_index.ntotal
        )

    # ==================================================
    # LANGUAGE DETECTION
    # ==================================================

    def detect_language(
        self,
        code: str
    ) -> str:

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

        for indicator in cpp_indicators:

            if indicator in code:

                return "cpp"

        return "c"

    # ==================================================
    # SECURITY QUERY
    # ==================================================

    def build_security_query(
        self,
        code: str
    ) -> str:

        lower_code = code.lower()

        mechanisms = []

        # ------------------------------------------
        # MEMORY SAFETY
        # ------------------------------------------

        if any(
            keyword in lower_code
            for keyword in [
                "strcpy",
                "strcat",
                "sprintf",
                "gets",
                "memcpy",
                "memmove",
                "memset",
                "buffer",
                "malloc",
                "calloc",
                "realloc",
                "free",
                "pointer",
                "argv",
                "scanf"
            ]
        ):

            mechanisms.append(
                "memory corruption buffer overflow "
                "unsafe memory operation"
            )

        # ------------------------------------------
        # INJECTION
        # ------------------------------------------

        if any(
            keyword in lower_code
            for keyword in [
                "system",
                "popen",
                "exec",
                "eval",
                "query",
                "sql"
            ]
        ):

            mechanisms.append(
                "command injection SQL injection "
                "code injection"
            )

        # ------------------------------------------
        # FORMAT STRING
        # ------------------------------------------

        if any(
            keyword in lower_code
            for keyword in [
                "printf",
                "fprintf",
                "sprintf",
                "snprintf"
            ]
        ):

            mechanisms.append(
                "format string vulnerability"
            )

        # ------------------------------------------
        # FILE ACCESS
        # ------------------------------------------

        if any(
            keyword in lower_code
            for keyword in [
                "fopen",
                "open(",
                "read(",
                "write(",
                "unlink",
                "remove"
            ]
        ):

            mechanisms.append(
                "file access path traversal "
                "file manipulation"
            )

        mechanism_text = " ".join(
            mechanisms
        )

        return f"""
Software security vulnerability analysis.

Analyze this source code for security relevance.

Source code:
{code}

Potential vulnerability mechanisms:
{mechanism_text}

Focus on:

- vulnerability mechanism
- unsafe operation
- attacker-controlled input
- data flow to dangerous operations
- memory safety
- injection
- authentication
- authorization
- file access
- CWE relevance
- security consequences
- vulnerable code similarity
- secure remediation similarity
"""

    # ==================================================
    # CWE DETECTION
    # ==================================================

    def detect_relevant_cwes(
        self,
        code: str
    ) -> set:

        lower_code = code.lower()

        detected = set()

        # ------------------------------------------
        # MEMORY SAFETY
        # ------------------------------------------

        memory_indicators = [
            "strcpy",
            "strcat",
            "sprintf",
            "gets",
            "memcpy",
            "memmove",
            "memset",
            "buffer",
            "malloc",
            "calloc",
            "realloc",
            "free",
            "pointer",
            "argv",
            "scanf"
        ]

        # ------------------------------------------
        # INJECTION
        # ------------------------------------------

        injection_indicators = [
            "system",
            "popen",
            "exec",
            "eval",
            "query",
            "sql"
        ]

        # ------------------------------------------
        # FORMAT STRING
        # ------------------------------------------

        format_indicators = [
            "printf",
            "fprintf",
            "sprintf",
            "snprintf"
        ]

        # ------------------------------------------
        # FILE ACCESS
        # ------------------------------------------

        file_indicators = [
            "fopen",
            "open",
            "read",
            "write",
            "unlink",
            "remove"
        ]

        if any(
            item in lower_code
            for item in memory_indicators
        ):

            detected.update({
                "CWE-119",
                "CWE-120",
                "CWE-121",
                "CWE-122",
                "CWE-125",
                "CWE-787",
                "CWE-788",
                "CWE-416",
                "CWE-476"
            })

        if any(
            item in lower_code
            for item in injection_indicators
        ):

            detected.update({
                "CWE-74",
                "CWE-77",
                "CWE-78",
                "CWE-89",
                "CWE-90",
                "CWE-91",
                "CWE-94"
            })

        if any(
            item in lower_code
            for item in format_indicators
        ):

            detected.add(
                "CWE-134"
            )

        if any(
            item in lower_code
            for item in file_indicators
        ):

            detected.update({
                "CWE-22",
                "CWE-23",
                "CWE-59",
                "CWE-73"
            })

        return detected

    # ==================================================
    # SEARCH
    # ==================================================

    def search(
        self,
        code: str,
        top_k: int = 5
    ) -> list:

        if not code.strip():

            return []

        retrieval_k = max(
            RETRIEVAL_POOL_SIZE,
            top_k
        )

        # ==========================================
        # LANGUAGE
        # ==========================================

        language = self.detect_language(
            code
        )

        print(
            "Detected language:",
            language
        )

        # ==========================================
        # CODE EMBEDDING
        # ==========================================

        code_embedding = self.model.encode(
            [code],
            normalize_embeddings=True,
            convert_to_numpy=True
        )

        # ==========================================
        # CODE SEARCH
        # ==========================================

        code_scores, code_indices = (
            self.code_index.search(
                code_embedding,
                retrieval_k
            )
        )

        # ==========================================
        # AST INDEX
        # ==========================================

        if language == "cpp":

            ast_service = (
                self.cpp_ast_service
            )

            ast_index = (
                self.cpp_ast_index
            )

            ast_metadata = (
                self.cpp_ast_metadata
            )

        else:

            ast_service = (
                self.c_ast_service
            )

            ast_index = (
                self.c_ast_index
            )

            ast_metadata = (
                self.c_ast_metadata
            )

        # ==========================================
        # AST REPRESENTATION
        # ==========================================

        try:

            ast_text = (
                ast_service.get_semantic_ast(
                    code
                )
            )

        except Exception as error:

            print(
                "AST generation failed:",
                error
            )

            ast_text = ""

        # ==========================================
        # AST SEARCH
        # ==========================================

        if ast_text:

            ast_embedding = self.model.encode(
                [ast_text],
                normalize_embeddings=True,
                convert_to_numpy=True
            )

            ast_scores, ast_indices = (
                ast_index.search(
                    ast_embedding,
                    retrieval_k
                )
            )

        else:

            ast_scores = [[]]
            ast_indices = [[]]

        # ==========================================
        # SECURITY SEARCH
        # ==========================================

        security_query = (
            self.build_security_query(
                code
            )
        )

        security_embedding = (
            self.model.encode(
                [security_query],
                normalize_embeddings=True,
                convert_to_numpy=True
            )
        )

        security_scores, security_indices = (
            self.security_index.search(
                security_embedding,
                retrieval_k
            )
        )

        # ==========================================
        # CANDIDATES
        # ==========================================

        candidates = {}

        def get_record_id(
            metadata,
            fallback
        ):

            record_id = metadata.get(
                "record_id"
            )

            if record_id is None:

                return fallback

            return record_id

        def create_candidate(
            metadata
        ):

            return {
                "metadata": metadata,

                "code_similarity": 0.0,
                "ast_similarity": 0.0,
                "security_similarity": 0.0,

                "code_rank": None,
                "ast_rank": None,
                "security_rank": None,

                "code_found": False,
                "ast_found": False,
                "security_found": False
            }

        # ==========================================
        # CODE CANDIDATES
        # ==========================================

        for rank, index in enumerate(
            code_indices[0]
        ):

            if index < 0:
                continue

            metadata = (
                self.code_metadata[index]
            )

            record_id = get_record_id(
                metadata,
                f"code_{index}"
            )

            if record_id not in candidates:

                candidates[record_id] = (
                    create_candidate(
                        metadata
                    )
                )

            candidate = candidates[
                record_id
            ]

            candidate[
                "code_similarity"
            ] = float(
                code_scores[0][rank]
            )

            candidate[
                "code_rank"
            ] = rank + 1

            candidate[
                "code_found"
            ] = True

        # ==========================================
        # AST CANDIDATES
        # ==========================================

        for rank, index in enumerate(
            ast_indices[0]
        ):

            if index < 0:
                continue

            metadata = (
                ast_metadata[index]
            )

            record_id = get_record_id(
                metadata,
                f"ast_{index}"
            )

            if record_id not in candidates:

                candidates[record_id] = (
                    create_candidate(
                        metadata
                    )
                )

            candidate = candidates[
                record_id
            ]

            candidate[
                "ast_similarity"
            ] = float(
                ast_scores[0][rank]
            )

            candidate[
                "ast_rank"
            ] = rank + 1

            candidate[
                "ast_found"
            ] = True

        # ==========================================
        # SECURITY CANDIDATES
        # ==========================================

        for rank, index in enumerate(
            security_indices[0]
        ):

            if index < 0:
                continue

            metadata = (
                self.security_metadata[index]
            )

            record_id = get_record_id(
                metadata,
                f"security_{index}"
            )

            if record_id not in candidates:

                candidates[record_id] = (
                    create_candidate(
                        metadata
                    )
                )

            candidate = candidates[
                record_id
            ]

            candidate[
                "security_similarity"
            ] = float(
                security_scores[0][rank]
            )

            candidate[
                "security_rank"
            ] = rank + 1

            candidate[
                "security_found"
            ] = True

        # ==========================================
        # QUERY CWE SIGNAL
        # ==========================================

        relevant_cwes = (
            self.detect_relevant_cwes(
                code
            )
        )

        print(
            "Relevant CWEs:",
            sorted(relevant_cwes)
        )

        # ==========================================
        # SCORE
        # ==========================================

        results = []

        for candidate in candidates.values():

            metadata = candidate[
                "metadata"
            ]

            code_similarity = candidate[
                "code_similarity"
            ]

            ast_similarity = candidate[
                "ast_similarity"
            ]

            security_similarity = candidate[
                "security_similarity"
            ]

            # --------------------------------------
            # BASE MULTI-VIEW SCORE
            # --------------------------------------

            base_score = (
                CODE_WEIGHT
                * code_similarity
                +
                AST_WEIGHT
                * ast_similarity
                +
                SECURITY_WEIGHT
                * security_similarity
            )

            # --------------------------------------
            # SECURITY BOOST
            # --------------------------------------

            security_boost = (
                SECURITY_BOOST_WEIGHT
                * security_similarity
            )

            # --------------------------------------
            # AST RANK BOOST
            # --------------------------------------

            ast_rank_boost = 0.0

            if candidate["ast_rank"] is not None:

                ast_rank = candidate[
                    "ast_rank"
                ]

                ast_rank_boost = (
                    0.12
                    * (
                        1.0
                        -
                        (
                            (ast_rank - 1)
                            /
                            retrieval_k
                        )
                    )
                )

            # --------------------------------------
            # CWE MATCHING
            # --------------------------------------

            record_cwes = metadata.get(
                "cwe",
                []
            )

            if not isinstance(
                record_cwes,
                list
            ):

                record_cwes = [
                    str(record_cwes)
                ]

            record_cwes = set(
                str(cwe)
                for cwe in record_cwes
            )

            cwe_matches = (
                relevant_cwes
                .intersection(
                    record_cwes
                )
            )

            # --------------------------------------
            # CWE BONUS
            # --------------------------------------

            cwe_bonus = 0.0

            if len(cwe_matches) >= 1:

                cwe_bonus = (
                    CWE_RELEVANCE_BONUS
                )

            if len(cwe_matches) >= 2:

                cwe_bonus += (
                    CWE_MULTI_MATCH_BONUS
                )

            # --------------------------------------
            # AGREEMENT BONUS
            # --------------------------------------

            views_found = sum([
                candidate["code_found"],
                candidate["ast_found"],
                candidate["security_found"]
            ])

            agreement_bonus = 0.0

            if views_found >= 2:

                agreement_bonus = (
                    AGREEMENT_BONUS
                )

            # --------------------------------------
            # FINAL SCORE
            # --------------------------------------

            final_score = (
                base_score
                +
                security_boost
                +
                ast_rank_boost
                +
                cwe_bonus
                +
                agreement_bonus
            )

            results.append({

                "record_id":
                    metadata.get(
                        "record_id"
                    ),

                "final_score":
                    final_score,

                "base_score":
                    base_score,

                "security_boost":
                    security_boost,

                "ast_rank_boost":
                    ast_rank_boost,

                "cwe_bonus":
                    cwe_bonus,

                "cwe_matches":
                    sorted(
                        cwe_matches
                    ),

                "agreement_bonus":
                    agreement_bonus,

                "code_similarity":
                    code_similarity,

                "ast_similarity":
                    ast_similarity,

                "security_similarity":
                    security_similarity,

                "code_found":
                    candidate[
                        "code_found"
                    ],

                "ast_found":
                    candidate[
                        "ast_found"
                    ],

                "security_found":
                    candidate[
                        "security_found"
                    ],

                "code_rank":
                    candidate[
                        "code_rank"
                    ],

                "ast_rank":
                    candidate[
                        "ast_rank"
                    ],

                "security_rank":
                    candidate[
                        "security_rank"
                    ],

                "vulnerable":
                    metadata.get(
                        "vulnerable",
                        False
                    ),

                "cwe":
                    metadata.get(
                        "cwe",
                        []
                    ),

                "project":
                    metadata.get(
                        "project",
                        ""
                    ),

                "commit_id":
                    metadata.get(
                        "commit_id",
                        ""
                    ),

                "message":
                    metadata.get(
                        "message",
                        ""
                    ),

                "code":
                    metadata.get(
                        "code",
                        ""
                    )
            })

        # ==========================================
        # SORT
        # ==========================================

        results.sort(
            key=lambda item:
                item["final_score"],
            reverse=True
        )

        return results[:top_k]


# ==================================================
# TEST
# ==================================================

if __name__ == "__main__":

    test_code = """
#include <stdio.h>

void print_input(char *input)
{
    printf(input);
}
"""

    retriever = MultiViewRetriever()

    results = retriever.search(
        test_code,
        top_k=5
    )

    print()
    print(
        "======================================"
    )

    print(
        "MULTI-VIEW RETRIEVAL RESULTS"
    )

    print(
        "======================================"
    )

    for i, result in enumerate(
        results,
        start=1
    ):

        print()
        print(
            f"RESULT {i}"
        )

        print(
            "Record ID:",
            result["record_id"]
        )

        print(
            "Project:",
            result["project"]
        )

        print(
            "Final score:",
            round(
                result["final_score"],
                5
            )
        )

        print(
            "Base score:",
            round(
                result["base_score"],
                5
            )
        )

        print(
            "Code similarity:",
            round(
                result["code_similarity"],
                5
            )
        )

        print(
            "AST similarity:",
            round(
                result["ast_similarity"],
                5
            )
        )

        print(
            "Security similarity:",
            round(
                result["security_similarity"],
                5
            )
        )

        print(
            "AST rank boost:",
            round(
                result["ast_rank_boost"],
                5
            )
        )

        print(
            "CWE bonus:",
            round(
                result["cwe_bonus"],
                5
            )
        )

        print(
            "CWE matches:",
            result["cwe_matches"]
        )

        print(
            "Code rank:",
            result["code_rank"]
        )

        print(
            "AST rank:",
            result["ast_rank"]
        )

        print(
            "Security rank:",
            result["security_rank"]
        )

        print(
            "Agreement bonus:",
            result["agreement_bonus"]
        )

        print(
            "CWE:",
            result["cwe"]
        )