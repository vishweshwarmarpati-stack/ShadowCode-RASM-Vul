ShadowCode
Retrieval-Augmented Semantic Mapping for Vulnerability Detection via Multi-View Code Similarity
Project Domain: Cyber Security
Application Area: Vulnerability Detection using
Retrieval-Augmented Generation (RAG)

1. Overview
ShadowCode is a vulnerability-detection project based on the
Retrieval-Augmented Semantic Mapping for Vulnerability Detection via
Multi-View Code Similarity (RASM-Vul) approach.

The central idea is to avoid relying on only one representation of
source code. Instead, the system retrieves evidence from multiple views
of code and vulnerability information, combines that evidence, and
provides it to a Large Language Model (LLM) for vulnerability analysis.

The approach is particularly intended to address cases where vulnerable
code and its fixed version are highly similar at the lexical level but
differ in a small statement-level or structural change.

2. Problem Statement
Traditional code-similarity or vulnerability-detection approaches can
struggle when a vulnerable function and its patched version look almost
identical.

For example, a security fix may involve:

adding a missing validation check,

changing a statement,

changing the scope of an operation,

modifying control flow,

or making a structural change in the Abstract Syntax Tree (AST).

A system that only compares source-code text may not capture these
differences sufficiently.

ShadowCode addresses this by combining multiple forms of evidence
rather than relying on a single retrieval channel.

3. Core Idea
The system follows this general pipeline:

Historical Vulnerable/Fix Data
            |
            v
   Knowledge Base Construction
            |
            v
    Multi-View Representations
            |
            v
     Multiple Vector Indices
            |
            v
        New Source Code
            |
            v
      Feature Analysis
            |
            v
    Multi-View Retrieval
            |
            v
   WRRF Adaptive Fusion
            |
            v
       LLM Re-ranking
            |
            v
       RAG Detection
            |
            v
 Vulnerability Result + Evidence
4. Multi-View Representation
ShadowCode uses five major retrieval views/indices.

4.1 Code Index
Represents the semantic/functional information contained in source code.

It helps retrieve historically similar code based on code-level meaning.

4.2 AST / Syntax Index
Represents the structural organization of code using Abstract Syntax
Tree information.

It helps identify structural vulnerability patterns that may not be
obvious from plain source-code similarity.

4.3 Knowledge Index
Stores vulnerability-related knowledge such as vulnerability semantics,
classification information, and remediation-related context.

This provides security knowledge in addition to code similarity.

4.4 Line-Change Index
Represents statement/line-level changes between vulnerable and fixed
versions.

This captures historical repair patterns and helps identify subtle
security fixes.

4.5 AST-Change Index
Represents structural changes between vulnerable and fixed versions.

This is useful when the security fix changes the structure of a program
rather than simply changing text.

5. Why Multiple Views?
A vulnerability can appear in different ways.

For example:

Statement-level problem
        |
        +--> Source-code similarity
        +--> Line-change evidence
while a structural problem may require:

Structural problem
        |
        +--> AST similarity
        +--> AST-change evidence
Therefore, the system does not treat every vulnerability as if the same
type of evidence were equally useful.

6. Adaptive Retrieval with WRRF
The system uses Weighted Reciprocal Rank Fusion (WRRF) to combine
results from different retrieval channels.

Instead of simply taking one retrieval result or treating all channels
equally, WRRF combines their rankings using weights.

Conceptually:

             Code Retrieval
                   |
             AST Retrieval
                   |
          Knowledge Retrieval
                   |
         Line-Change Retrieval
                   |
          AST-Change Retrieval
                   |
                   v
          +----------------+
          |      WRRF      |
          | Weighted Rank  |
          |     Fusion     |
          +-------+--------+
                  |
                  v
       Combined Relevant Evidence
The purpose is to adapt the evidence contribution to the characteristics
of the vulnerability.

For statement-level vulnerabilities, code and line-change evidence can
be particularly important.

For structural-level vulnerabilities, AST and AST-change evidence can
become more important.

7. Retrieval-Augmented Generation (RAG)
RAG means that the LLM does not have to depend only on knowledge learned
during training.

Instead:

User Code
   |
   v
Retrieve Relevant Evidence
   |
   +--> Similar Code
   +--> AST Patterns
   +--> Vulnerability Knowledge
   +--> Historical Line Changes
   +--> Historical AST Changes
   |
   v
Construct Context
   |
   v
LLM
   |
   v
Vulnerability Analysis
The retrieved evidence provides additional context to the LLM before it
produces the final analysis.

8. Two-Phase Architecture
Phase A --- Offline Knowledge-Base Construction
Historical vulnerability/fix data and vulnerability knowledge are
processed before online detection.

Historical Data
      |
      v
Knowledge Extraction
      |
      v
Code / Fix Processing
      |
      v
Multi-View Representation
      |
      v
Vectorization
      |
      v
Five Retrieval Indices
The resulting vector knowledge base can then be used during
vulnerability detection.

Phase B --- Online Vulnerability Detection
When new code is submitted:

New Code
   |
   v
Feature Analysis
   |
   v
Problem-Type Analysis
   |
   v
Multi-View Retrieval
   |
   v
WRRF Fusion
   |
   v
LLM Re-ranking
   |
   v
RAG-based Detection
   |
   v
Final Result
9. Vertical Data Flow: One Code Example
Consider a code fragment containing user-controlled input that reaches a
database operation.

The system can process it as follows:

                Input Code
                    |
                    v
             Feature Analysis
                    |
                    v
       +------------+------------+
       |            |            |
       v            v            v
     Code          AST       Knowledge
       |            |            |
       +------------+------------+
                    |
             Change Evidence
              /           \
             v             v
       Line Changes     AST Changes
             \             /
              \           /
               v         v
                 Retrieval
                    |
                    v
                   WRRF
                    |
                    v
             Relevant Evidence
                    |
                    v
                LLM / RAG
                    |
                    v
          Vulnerability Assessment
The important point is that the final assessment is supported by
retrieved historical and security evidence.

10. ⭐ Project Differentiator
Adaptive Multi-View Vulnerability Mapping
The key architectural differentiator proposed for ShadowCode is the
combination of:

Multiple code representations

Historical repair evidence

Vulnerability knowledge

Adaptive WRRF retrieval

RAG-based LLM analysis

The goal is not simply to output:

VULNERABLE
but to make the result evidence-oriented:

Vulnerability
      |
      +--> Semantic evidence
      +--> Structural evidence
      +--> Historical repair evidence
      +--> Security knowledge
      +--> Retrieved similar cases
Proposed future-facing output
A final ShadowCode interface can be designed to show:

Vulnerability Detected
----------------------
Type / CWE:
Suspicious Code:
Relevant Historical Example:
Semantic Evidence:
Structural Evidence:
Repair Evidence:
Retrieval Relevance:
Suggested Remediation:
The evidence-oriented interface above is a proposed project feature
for ShadowCode. It should not be presented as an already-existing
feature of the source paper unless it has been implemented.

11. Why Not Just Use a General Coding Assistant?
ShadowCode is designed specifically around vulnerability detection and
evidence retrieval.

Its focus is not simply code generation or general coding assistance.

The system is designed to answer a more specific security question:

"What historical and structural evidence supports the conclusion
that this code resembles a known vulnerable pattern?"

The distinguishing architectural idea is therefore the combination of
multi-view retrieval, historical repair evidence, adaptive fusion, and
RAG-based vulnerability analysis.

12. Important Concepts
Concept Simple Meaning

RAG Retrieve useful information before
asking the LLM to generate an
answer

Vector Database Stores vector representations so
similar items can be retrieved

Embedding Numerical representation of code or
knowledge

AST Tree representation of program
structure

Multi-View Similarity Comparing code using more than one
representation

Line Change Difference between vulnerable and
fixed code at line/statement level

AST Change Structural difference between
vulnerable and fixed code

WRRF Weighted method for combining
ranked results from multiple
retrieval channels

CWE Classification system for types of
software weaknesses

CVE Identifier for publicly disclosed
vulnerabilities

LLM Large Language Model

13. Expected Workflow
1. Collect historical vulnerable/fixed code
                    |
                    v
2. Extract vulnerability knowledge
                    |
                    v
3. Generate multi-view representations
                    |
                    v
4. Build vector indices
                    |
                    v
5. Accept new source code
                    |
                    v
6. Analyze code characteristics
                    |
                    v
7. Retrieve evidence from multiple views
                    |
                    v
8. Fuse rankings using WRRF
                    |
                    v
9. Re-rank relevant evidence
                    |
                    v
10. Provide retrieved context to LLM
                    |
                    v
11. Produce vulnerability assessment
                    |
                    v
12. Present evidence and remediation
14. Research Foundation
The project is based on the RASM-Vul research framework described in:

"Retrieval-Augmented Semantic Mapping for Vulnerability Detection via
Multi-View Code Similarity"

The paper reports experiments using the PrimeVul Paired dataset and
evaluates multi-view retrieval, WRRF, and vulnerability detection
performance.

Reported results include:

Full RASM-Vul with DeepSeek-V3: 66.79% F1-score

Full RASM-Vul with Qwen2.5-72B: 64.96% F1-score

Paired detection accuracy with the WRRF configuration: 21.38%

WRRF F1-score in the reported retrieval ablation: 66.79%

These figures are research-paper results, not guaranteed results for
the ShadowCode implementation. The project's own results should be
reported separately after experimentation.

15. Current Limitations to Keep in Mind
The source research reports several limitations that are relevant when
extending the project:

The reported experiments are primarily limited to C/C++.

The framework operates at function level rather than full repository
level.

Cross-function and cross-file vulnerabilities can be difficult to
detect.

Systems based on historical examples may struggle with unique or
zero-day vulnerability patterns that have little or no
representation in the knowledge base.

Retrieval quality depends strongly on the quality and diversity of
the underlying data.

These limitations should be considered when defining the project's
scope.

16. Future Development Direction
Potential extensions for ShadowCode include:

Evidence-oriented vulnerability explanations

Better visualization of retrieved vulnerable/fixed pairs

Repository-level context

Caller/callee relationship analysis

Additional programming languages

Improved retrieval confidence indicators

Interactive vulnerability reports

Automated remediation suggestions

Evaluation on the project's final curated dataset

17. Project Structure
A suggested implementation structure is:

ShadowCode/
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── knowledge_base/
│
├── preprocessing/
│   ├── code_processing/
│   ├── ast_processing/
│   └── diff_processing/
│
├── embeddings/
│   └── ...
│
├── vector_db/
│   ├── code_index/
│   ├── ast_index/
│   ├── knowledge_index/
│   ├── line_change_index/
│   └── ast_change_index/
│
├── retrieval/
│   ├── multi_view_retrieval/
│   └── wrrf/
│
├── rag/
│   ├── prompts/
│   └── inference/
│
├── evaluation/
│   └── ...
│
├── app/
│   └── ...
│
├── requirements.txt
└── README.md
This directory layout is a suggested organization for the
implementation. It is not claimed to be the exact source-paper
repository structure.

18. Evaluation
The project should evaluate at least:

Accuracy

Precision

Recall

F1-score

Paired detection accuracy

Retrieval relevance

False positives

False negatives

Ablation experiments can also be used to determine the contribution of:

Code only
      vs
Code + Line Changes
      vs
AST + AST Changes
      vs
Knowledge-enhanced retrieval
      vs
Full Multi-View + WRRF
19. Key Takeaway
ShadowCode can be summarized in one sentence:

ShadowCode detects vulnerabilities by retrieving and adaptively
combining semantic, structural, security-knowledge, and
historical-repair evidence before using an LLM to perform
vulnerability analysis.

20. References
The architecture and terminology in this README are based on the
uploaded RASM-Vul research paper:

Retrieval-Augmented Semantic Mapping for Vulnerability Detection via
Multi-View Code Similarity.

DOI: 10.3390/electronics15030612

The research paper reports the experimental methodology, multi-view
retrieval architecture, WRRF retrieval strategy, paired detection
analysis, and limitations described above.
