import { useState, useEffect } from "react";
import "./App.css";
import hackerAvatar from "./assets/shadowcode-hacker.svg";

// Local FastAPI backend
const API = (import.meta.env.VITE_API_URL || "https://shadow-code-backend.onrender.com").replace(/\/$/, "");

const demoCode = `from flask import request
import sqlite3

user = request.args.get("user")

query = "SELECT * FROM users WHERE name = '" + user + "'"`;

function App() {
  const [activeTab, setActiveTab] = useState("overview");

  // ============================================================
  // CODE ANALYZER STATE
  // ============================================================

  const [code, setCode] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // ============================================================
  // REPOSITORY SCANNER STATE
  // ============================================================

  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [repoResult, setRepoResult] = useState(null);
  const [repoLoading, setRepoLoading] = useState(false);
  const [repoError, setRepoError] = useState("");

  // ============================================================
  // SANDBOX STATE
  // ============================================================

  const [sandboxCode, setSandboxCode] = useState(
    'print("ShadowCode Sandbox OK")'
  );
  const [sandboxResult, setSandboxResult] = useState(null);
  const [sandboxLoading, setSandboxLoading] = useState(false);
  const [sandboxError, setSandboxError] = useState("");

  // ============================================================
  // AI ASSISTANT STATE
  // ============================================================

  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState("");

  // ============================================================
  // GENERAL STATE
  // ============================================================

  const [error, setError] = useState("");
  const [engineOnline, setEngineOnline] = useState(false);

  // ============================================================
  // HEALTH CHECK
  // ============================================================

  useEffect(() => {
    let cancelled = false;

    const checkHealth = async () => {
      try {
        const response = await fetch(`${API}/health`);

        if (!cancelled) {
          setEngineOnline(response.ok);
        }
      } catch (err) {
        if (!cancelled) {
          setEngineOnline(false);
        }
      }
    };

    checkHealth();

    return () => {
      cancelled = true;
    };
  }, []);

  // ============================================================
  // RESPONSE HELPERS
  // ============================================================

  const parseJsonResponse = async (response) => {
    const text = await response.text();

    if (!text) {
      return {};
    }

    try {
      return JSON.parse(text);
    } catch {
      return {
        detail: text,
      };
    }
  };

  const getErrorMessage = (data, fallback) => {
    if (!data) {
      return fallback;
    }

    if (typeof data.detail === "string") {
      return data.detail;
    }

    if (typeof data.error === "string") {
      return data.error;
    }

    if (typeof data.message === "string") {
      return data.message;
    }

    return fallback;
  };

  const normalizeFindings = (data) => {
    if (!data) {
      return [];
    }

    if (Array.isArray(data)) {
      return data;
    }

    if (Array.isArray(data.vulnerabilities)) {
      return data.vulnerabilities;
    }

    if (Array.isArray(data.findings)) {
      return data.findings;
    }

    if (data.result && Array.isArray(data.result.vulnerabilities)) {
      return data.result.vulnerabilities;
    }

    if (data.result && Array.isArray(data.result.findings)) {
      return data.result.findings;
    }

    return [];
  };

  // ============================================================
  // CODE ANALYZER
  // ============================================================

  const analyzeCode = async () => {
    if (!code.trim()) {
      setError("Please paste some source code first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          code: code,
        }),
      });

      const data = await parseJsonResponse(response);

      console.log("Code analysis response:", data);

      if (!response.ok) {
        throw new Error(
          getErrorMessage(
            data,
            `Backend returned ${response.status}`
          )
        );
      }

      setResult(data);
    } catch (err) {
      console.error("Code analysis failed:", err);

      setError(
        err.message ||
          "Could not connect to ShadowCode backend. Please check that the backend is online."
      );
    } finally {
      setLoading(false);
    }
  };

  const loadDemo = () => {
    setCode(demoCode);
    setResult(null);
    setError("");
    setActiveTab("analyzer");
  };

  // ============================================================
  // REPOSITORY SCANNER
  // ============================================================

  const scanRepository = async () => {
    const url = repositoryUrl.trim();

    if (!url) {
      setRepoError("Please enter a GitHub repository URL.");
      return;
    }

    if (!url.startsWith("https://github.com/")) {
      setRepoError(
        "Please enter a valid GitHub repository URL, for example: https://github.com/user/repository"
      );
      return;
    }

    // Remove accidental /tree/main or /tree/master
    const cleanedUrl = url
      .replace(/\/tree\/main\/?$/, "")
      .replace(/\/tree\/master\/?$/, "")
      .replace(/\/$/, "");

    setRepoLoading(true);
    setRepoError("");
    setRepoResult(null);

    try {
      console.log("Scanning repository:", cleanedUrl);

      const response = await fetch(`${API}/analyze/repository`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          repository_url: cleanedUrl,
        }),
      });

      const data = await parseJsonResponse(response);

      console.log("Repository scan response:", data);

      if (!response.ok) {
        throw new Error(
          getErrorMessage(
            data,
            `Repository scanner returned ${response.status}`
          )
        );
      }

      const normalizedData = {
        ...data,
        repository_url:
          data.repository_url ||
          data.repository ||
          cleanedUrl,
        vulnerabilities: normalizeFindings(data),
        total_vulnerabilities:
          typeof data.total_vulnerabilities === "number"
            ? data.total_vulnerabilities
            : normalizeFindings(data).length,
        files_analyzed:
          typeof data.files_analyzed === "number"
            ? data.files_analyzed
            : 0,
        severity_summary:
          data.severity_summary || {},
      };

      setRepoResult(normalizedData);
    } catch (err) {
      console.error("Repository scan failed:", err);

      setRepoError(
        err.message ||
          "Could not scan repository. Please check that the backend is running."
      );
    } finally {
      setRepoLoading(false);
    }
  };

  // ============================================================
  // SANDBOX VERIFICATION
  // ============================================================

  const verifySandbox = async () => {
    if (!sandboxCode.trim()) {
      setSandboxError("Please enter Python code first.");
      return;
    }

    setSandboxLoading(true);
    setSandboxError("");
    setSandboxResult(null);

    try {
      console.log("Sending code to sandbox...");

      const response = await fetch(`${API}/sandbox/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          code: sandboxCode,
        }),
      });

      const data = await parseJsonResponse(response);

      console.log("Sandbox response:", data);

      if (!response.ok) {
        throw new Error(
          getErrorMessage(
            data,
            `Sandbox returned ${response.status}`
          )
        );
      }

      setSandboxResult({
        ...data,
        status: data.status || "UNKNOWN",
        exit_code:
          data.exit_code !== undefined
            ? data.exit_code
            : null,
        output: data.output || "",
        error: data.error || "",
      });
    } catch (err) {
      console.error("Sandbox verification failed:", err);

      setSandboxError(
        err.message ||
          "Sandbox verification failed. Please check that the backend is running."
      );
    } finally {
      setSandboxLoading(false);
    }
  };

  // ============================================================
  // AI ASSISTANT
  // ============================================================

  const sendChat = async () => {
    const message = chatInput.trim();

    if (!message || chatLoading) {
      return;
    }

    setChatMessages((previous) => [
      ...previous,
      {
        role: "user",
        content: message,
      },
    ]);

    setChatInput("");
    setChatLoading(true);
    setChatError("");

    try {
      const response = await fetch(`${API}/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          message: message,
        }),
      });

      const data = await parseJsonResponse(response);

      console.log("AI response:", data);

      if (!response.ok) {
        throw new Error(
          getErrorMessage(
            data,
            `AI Assistant returned ${response.status}`
          )
        );
      }

      setChatMessages((previous) => [
        ...previous,
        {
          role: "assistant",
          content:
            data.response ||
            data.message ||
            "ShadowCode did not return a response.",
        },
      ]);
    } catch (err) {
      console.error("AI Assistant failed:", err);

      setChatError(
        err.message ||
          "Could not connect to ShadowCode AI."
      );
    } finally {
      setChatLoading(false);
    }
  };

  // ============================================================
  // NAVIGATION
  // ============================================================

  const goToAnalyzer = () => {
    setActiveTab("analyzer");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const goToRepoScanner = () => {
    setActiveTab("repo");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const goToSandbox = () => {
    setActiveTab("sandbox");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const goToAssistant = () => {
    setActiveTab("assistant");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  // ============================================================
  // RESULTS
  // ============================================================

  const findings = normalizeFindings(result);

  const repoFindings = normalizeFindings(repoResult);

  // ============================================================
  // HELPERS
  // ============================================================

  const getSeverityClass = (severity) => {
    return String(severity || "medium")
      .toLowerCase()
      .replace(/\s+/g, "-");
  };

  const getVerificationClass = (status) => {
    const normalized = String(
      status || "NOT_AVAILABLE"
    ).toUpperCase();

    if (
      normalized === "VERIFIED" ||
      normalized === "PASS" ||
      normalized === "PASSED"
    ) {
      return "verified";
    }

    if (
      normalized === "NOT_REPRODUCIBLE" ||
      normalized === "UNSUPPORTED" ||
      normalized === "NOT_AVAILABLE" ||
      normalized === "UNKNOWN"
    ) {
      return "not-verified";
    }

    if (
      normalized === "ERROR" ||
      normalized === "TIMEOUT" ||
      normalized === "FAILED" ||
      normalized === "FAIL"
    ) {
      return "verification-error";
    }

    return "not-verified";
  };

  const formatVerificationStatus = (status) => {
    const normalized = String(
      status || "NOT_AVAILABLE"
    ).toUpperCase();

    if (
      normalized === "VERIFIED" ||
      normalized === "PASS" ||
      normalized === "PASSED"
    ) {
      return "✓ VERIFIED";
    }

    return normalized.replace(/_/g, " ");
  };

  // ============================================================
  // UI
  // ============================================================

  return (
    <div className="app">
      {/* ======================================================
          NAVBAR
      ====================================================== */}

      <header className="navbar">
        <div
          className="brand"
          onClick={() => setActiveTab("overview")}
        >
          <div className="brand-logo">
            <img src={hackerAvatar} alt="ShadowCode cyber hacker" />
          </div>

          <div className="brand-text">
            <div className="brand-title">
              ShadowCode
              <span className="version">
                v1.0 DevSecOps
              </span>
            </div>

            <div className="brand-subtitle">
              AI-Powered Security Engine
            </div>
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={
              activeTab === "overview"
                ? "nav-tab active"
                : "nav-tab"
            }
            onClick={() =>
              setActiveTab("overview")
            }
          >
            <span>◈</span>
            Overview
          </button>

          <button
            className={
              activeTab === "analyzer"
                ? "nav-tab active"
                : "nav-tab"
            }
            onClick={() =>
              setActiveTab("analyzer")
            }
          >
            <span>&lt;/&gt;</span>
            Code Analyzer
          </button>

          <button
            className={
              activeTab === "repo"
                ? "nav-tab active"
                : "nav-tab"
            }
            onClick={() => setActiveTab("repo")}
          >
            <span>▣</span>
            Repo Scanner
          </button>

          <button
            className={
              activeTab === "sandbox"
                ? "nav-tab active"
                : "nav-tab"
            }
            onClick={() =>
              setActiveTab("sandbox")
            }
          >
            <span>›_</span>
            Sandbox Verifier
          </button>

          <button
            className={
              activeTab === "assistant"
                ? "nav-tab active"
                : "nav-tab"
            }
            onClick={() =>
              setActiveTab("assistant")
            }
          >
            <span>▱</span>
            AI Assistant
          </button>
        </nav>

        <div className="engine-status">
          <span
            className={`status-dot ${
              engineOnline ? "online" : "offline"
            }`}
          ></span>

          {engineOnline
            ? "Engine Online"
            : "Engine Offline"}
        </div>
      </header>

      {/* ======================================================
          OVERVIEW
      ====================================================== */}

      {activeTab === "overview" && (
        <main className="page">
          <section className="hero">
            <div className="hero-content">
              <div className="eyebrow">
                ⚡ MULTI-LAYER DEVSECOPS SECURITY
              </div>

              <h1>
                Autonomous AI Code
                <br />
                Security &amp; Sandbox Platform
              </h1>

              <p className="hero-description">
                ShadowCode combines AST analysis,
                AI-powered security detection,
                Docker sandbox execution, and Git
                repository scanning into one unified
                security platform.
              </p>

              <div className="hero-actions">
                <button
                  className="primary-button"
                  onClick={goToAnalyzer}
                >
                  Scan Code Now
                  <span>→</span>
                </button>

                <button
                  className="secondary-button"
                  onClick={goToRepoScanner}
                >
                  Scan Repository
                  <span>▣</span>
                </button>
              </div>
            </div>

            <div className="hero-card">
              <div className="hero-card-icon"><img src={hackerAvatar} alt="" aria-hidden="true" /></div>

              <h3>ShadowCode</h3>

              <p>Featherless.ai Powered</p>

              <div className="mini-status">
                <span
                  className={`status-dot ${
                    engineOnline
                      ? "online"
                      : "offline"
                  }`}
                ></span>

                {engineOnline
                  ? "Engine Online"
                  : "Engine Offline"}
              </div>
            </div>
          </section>

          <section className="feature-grid">
            <div className="feature-card">
              <div className="feature-icon">
                &lt;/&gt;
              </div>

              <h3>
                AST + AI Hybrid Analysis
              </h3>

              <p>
                Parses source code and combines
                structural analysis with AI-powered
                vulnerability evaluation.
              </p>

              <button onClick={goToAnalyzer}>
                Open Analyzer →
              </button>
            </div>

            <div className="feature-card">
              <div className="feature-icon">
                ›_
              </div>

              <h3>
                Sandbox Patch Verification
              </h3>

              <p>
                Applies security patches safely,
                executes tests, and verifies changes
                before merge.
              </p>

              <button onClick={goToSandbox}>
                Open Sandbox →
              </button>
            </div>

            <div className="feature-card">
              <div className="feature-icon">
                ◎
              </div>

              <h3>
                Featherless.ai Pipeline
              </h3>

              <p>
                AI inference pipeline for intelligent
                source-code security analysis and
                remediation.
              </p>

              <button onClick={goToAssistant}>
                Open AI Assistant →
              </button>
            </div>
          </section>

          <section className="workflow">
            <div className="section-heading">
              <span className="eyebrow">
                SECURITY WORKFLOW
              </span>

              <h2>
                From Code to Secure Release
              </h2>

              <p>
                A multi-layer pipeline designed to
                detect, understand and verify security
                issues.
              </p>
            </div>

            <div className="workflow-grid">
              <div className="workflow-step">
                <div className="step-number">
                  01
                </div>

                <h3>Analyze</h3>

                <p>
                  Parse source code and identify
                  suspicious patterns.
                </p>
              </div>

              <div className="workflow-line">
                →
              </div>

              <div className="workflow-step">
                <div className="step-number">
                  02
                </div>

                <h3>Detect</h3>

                <p>
                  Combine static analysis with AI
                  security evaluation.
                </p>
              </div>

              <div className="workflow-line">
                →
              </div>

              <div className="workflow-step">
                <div className="step-number">
                  03
                </div>

                <h3>Verify</h3>

                <p>
                  Safely validate security fixes
                  before deployment.
                </p>
              </div>
            </div>
          </section>
        </main>
      )}

      {/* ======================================================
          CODE ANALYZER
      ====================================================== */}

      {activeTab === "analyzer" && (
        <main className="page analyzer-page">
          <section className="analyzer-header">
            <div>
              <div className="eyebrow">
                CODE SECURITY ANALYZER
              </div>

              <h1>
                Find vulnerabilities before they
                ship.
              </h1>

              <p>
                Paste your source code and let
                ShadowCode perform a multi-layer
                security analysis.
              </p>
            </div>

            <div className="analyzer-badge">
              <span className="status-dot"></span>
              API /analyze
            </div>
          </section>

          <section className="editor-card">
            <div className="editor-toolbar">
              <div className="window-controls">
                <span></span>
                <span></span>
                <span></span>
              </div>

              <div className="file-name">
                security_test.py
              </div>

              <button
                className="demo-button"
                onClick={loadDemo}
              >
                Load Demo
              </button>
            </div>

            <div className="editor">
              <div className="line-numbers">
                {Array.from(
                  {
                    length: Math.max(
                      code.split("\n").length,
                      12
                    ),
                  },
                  (_, i) => (
                    <span key={i}>
                      {i + 1}
                    </span>
                  )
                )}
              </div>

              <textarea
                value={code}
                onChange={(e) => {
                  setCode(e.target.value);
                  setError("");
                }}
                spellCheck="false"
                placeholder="Paste your Python source code here..."
              />
            </div>

            <div className="editor-footer">
              <span>
                Python • Static Analysis + AI
              </span>

              <span>
                {code.length} characters
              </span>
            </div>
          </section>

          <div className="analyze-row">
            <button
              className="primary-button analyze-button"
              onClick={analyzeCode}
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Analyzing Security...
                </>
              ) : (
                <>
                  🔍 Analyze Security
                  <span>→</span>
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="error-box">
              ⚠ {error}
            </div>
          )}

          {result && (
            <section className="results-section">
              <div className="results-summary">
                <div>
                  <div className="eyebrow">
                    ANALYSIS COMPLETE
                  </div>

                  <h2>
                    Security Findings
                  </h2>
                </div>

                <div className="finding-count">
                  <strong>
                    {findings.length}
                  </strong>

                  <span>findings</span>
                </div>
              </div>

              {findings.length === 0 ? (
                <div className="safe-box">
                  <div className="safe-icon">
                    ✓
                  </div>

                  <div>
                    <h3>
                      No vulnerabilities detected
                    </h3>

                    <p>
                      ShadowCode did not identify
                      any security issues in the
                      submitted code.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="findings-list">
                  {findings.map(
                    (vulnerability, index) => (
                      <article
                        className="finding-card"
                        key={`${vulnerability.file || "code"}-${
                          vulnerability.line || "unknown"
                        }-${index}`}
                      >
                        <div className="finding-top">
                          <div>
                            <span className="finding-number">
                              FINDING #
                              {index + 1}
                            </span>

                            <h3>
                              {vulnerability.name ||
                                vulnerability.title ||
                                "Security Vulnerability"}
                            </h3>
                          </div>

                          <span
                            className={`severity ${getSeverityClass(
                              vulnerability.severity
                            )}`}
                          >
                            {vulnerability.severity ||
                              "MEDIUM"}
                          </span>
                        </div>

                        <div className="finding-grid">
                          <div>
                            <span className="field-label">
                              DESCRIPTION
                            </span>

                            <p>
                              {vulnerability.description ||
                                "Security issue detected in the submitted code."}
                            </p>
                          </div>

                          <div>
                            <span className="field-label">
                              EVIDENCE
                            </span>

                            <pre>
                              {vulnerability.evidence ||
                                "Evidence unavailable"}
                            </pre>
                          </div>

                          <div>
                            <span className="field-label">
                              IMPACT
                            </span>

                            <p>
                              {vulnerability.impact ||
                                "This issue may expose the application to security risks."}
                            </p>
                          </div>

                          <div>
                            <span className="field-label">
                              REMEDIATION
                            </span>

                            <p>
                              {vulnerability.remediation ||
                                "Review the vulnerable code and apply secure coding practices."}
                            </p>
                          </div>
                        </div>

                        {vulnerability.line !== undefined &&
                          vulnerability.line !== null && (
                            <div className="repo-location">
                              📍 Line{" "}
                              {vulnerability.line}
                            </div>
                          )}

                        {vulnerability.code && (
                          <div className="code-result vulnerable-code">
                            <span className="field-label">
                              VULNERABLE CODE
                            </span>

                            <pre>
                              {vulnerability.code}
                            </pre>
                          </div>
                        )}

                        {vulnerability.corrected_code && (
                          <div className="code-result corrected-code">
                            <span className="field-label">
                              CORRECTED CODE
                            </span>

                            <pre>
                              {vulnerability.corrected_code}
                            </pre>
                          </div>
                        )}

                        {vulnerability.verification_status && (
                          <div className="verification-result">
                            <span className="field-label">
                              VERIFICATION
                            </span>

                            <div
                              className={`verification-badge ${getVerificationClass(
                                vulnerability.verification_status
                              )}`}
                            >
                              {formatVerificationStatus(
                                vulnerability.verification_status
                              )}
                            </div>

                            {vulnerability.verification_reason && (
                              <p>
                                {
                                  vulnerability.verification_reason
                                }
                              </p>
                            )}
                          </div>
                        )}

                        <div className="confidence">
                          Confidence:{" "}
                          <strong>
                            {vulnerability.confidence ||
                              "HIGH"}
                          </strong>
                        </div>
                      </article>
                    )
                  )}
                </div>
              )}
            </section>
          )}
        </main>
      )}

            {/* ======================================================
          REPOSITORY SCANNER
      ====================================================== */}

      {activeTab === "repo" && (
        <main className="page analyzer-page repo-page">
          <section className="analyzer-header">
            <div>
              <div className="eyebrow">
                REPOSITORY SECURITY SCANNER
              </div>

              <h1>
                Scan an entire Git repository.
              </h1>

              <p>
                Enter a public GitHub repository URL
                and ShadowCode will clone and analyze
                its source files.
              </p>
            </div>

            <div className="analyzer-badge">
              <span className="status-dot"></span>
              API /analyze/repository
            </div>
          </section>

          <section className="editor-card repo-scanner-card">
            <div className="editor-toolbar">
              <div className="window-controls">
                <span></span>
                <span></span>
                <span></span>
              </div>

              <div className="file-name">
                GitHub Repository
              </div>
            </div>

            <div className="repo-input-container">
              <label htmlFor="repository-url">
                Repository URL
              </label>

              <input
                id="repository-url"
                type="url"
                value={repositoryUrl}
                onChange={(e) => {
                  setRepositoryUrl(e.target.value);
                  setRepoError("");
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    scanRepository();
                  }
                }}
                placeholder="https://github.com/username/repository"
                disabled={repoLoading}
              />

              <p className="repo-help">
                Example:
                https://github.com/username/repository
              </p>
            </div>

            <div className="editor-footer">
              <span>
                GitHub • Repository Security Analysis
              </span>

              <span>
                {repositoryUrl.length} characters
              </span>
            </div>
          </section>

          <div className="analyze-row">
            <button
              className="primary-button analyze-button"
              onClick={scanRepository}
              disabled={repoLoading}
            >
              {repoLoading ? (
                <>
                  <span className="spinner"></span>
                  Scanning Repository...
                </>
              ) : (
                <>
                  🔍 Scan Repository
                  <span>→</span>
                </>
              )}
            </button>
          </div>

          {repoError && (
            <div className="error-box">
              ⚠ {repoError}
            </div>
          )}

          {repoResult && (
            <section className="results-section">
              <div className="results-summary">
                <div>
                  <div className="eyebrow">
                    REPOSITORY SCAN COMPLETE
                  </div>

                  <h2>
                    Security Findings
                  </h2>

                  <p>
                    Repository:{" "}
                    {repoResult.repository_url ||
                      repositoryUrl}
                  </p>
                </div>

                <div className="finding-count">
                  <strong>
                    {repoFindings.length}
                  </strong>

                  <span>findings</span>
                </div>
              </div>

              <div className="feature-grid">
                <div className="feature-card">
                  <div className="feature-icon">
                    ▣
                  </div>

                  <h3>
                    Files Analyzed
                  </h3>

                  <p>
                    {repoResult.files_analyzed ||
                      0}{" "}
                    source files
                  </p>
                </div>

                <div className="feature-card">
                  <div className="feature-icon">
                    ⚠
                  </div>

                  <h3>
                    Vulnerabilities
                  </h3>

                  <p>
                    {repoFindings.length}{" "}
                    issues detected
                  </p>
                </div>

                <div className="feature-card">
                  <div className="feature-icon">
                    !
                  </div>

                  <h3>
                    High Severity
                  </h3>

                  <p>
                    {repoResult.severity_summary
                      ?.HIGH ||
                      repoResult.severity_summary
                        ?.high ||
                      0}{" "}
                    high-risk findings
                  </p>
                </div>
              </div>

              {repoFindings.length === 0 ? (
                <div className="safe-box">
                  <div className="safe-icon">
                    ✓
                  </div>

                  <div>
                    <h3>
                      No vulnerabilities detected
                    </h3>

                    <p>
                      ShadowCode did not identify
                      security vulnerabilities in
                      the scanned repository.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="findings-list">
                  {repoFindings.map(
                    (vulnerability, index) => (
                      <article
                        className="finding-card"
                        key={`${vulnerability.file || "unknown"}-${
                          vulnerability.line || "unknown"
                        }-${vulnerability.name || "finding"}-${index}`}
                      >
                        <div className="finding-top">
                          <div>
                            <span className="finding-number">
                              FINDING #
                              {index + 1}
                            </span>

                            <h3>
                              {vulnerability.name ||
                                vulnerability.title ||
                                "Security Vulnerability"}
                            </h3>

                            <div className="repo-file">
                              📄{" "}
                              {vulnerability.file ||
                                "Unknown file"}
                            </div>

                            {vulnerability.line !==
                              undefined &&
                              vulnerability.line !==
                                null && (
                                <div className="repo-location">
                                  📍 Line{" "}
                                  <strong>
                                    {vulnerability.line}
                                  </strong>
                                </div>
                              )}
                          </div>

                          <span
                            className={`severity ${getSeverityClass(
                              vulnerability.severity
                            )}`}
                          >
                            {vulnerability.severity ||
                              "MEDIUM"}
                          </span>
                        </div>

                        <div className="finding-grid">
                          <div>
                            <span className="field-label">
                              DESCRIPTION
                            </span>

                            <p>
                              {vulnerability.description ||
                                "Security issue detected."}
                            </p>
                          </div>

                          <div>
                            <span className="field-label">
                              EVIDENCE
                            </span>

                            <pre>
                              {vulnerability.evidence ||
                                "Evidence unavailable"}
                            </pre>
                          </div>

                          <div>
                            <span className="field-label">
                              IMPACT
                            </span>

                            <p>
                              {vulnerability.impact ||
                                "Potential security impact identified."}
                            </p>
                          </div>

                          <div>
                            <span className="field-label">
                              REMEDIATION
                            </span>

                            <p>
                              {vulnerability.remediation ||
                                "Apply secure coding practices."}
                            </p>
                          </div>
                        </div>

                        {/* Vulnerable source code */}
                        {vulnerability.code && (
                          <div className="code-result vulnerable-code">
                            <span className="field-label">
                              VULNERABLE CODE
                            </span>

                            <pre>
                              {vulnerability.code}
                            </pre>
                          </div>
                        )}

                        {/* Corrected source code */}
                        {vulnerability.corrected_code && (
                          <div className="code-result corrected-code">
                            <span className="field-label">
                              CORRECTED CODE
                            </span>

                            <pre>
                              {vulnerability.corrected_code}
                            </pre>
                          </div>
                        )}

                        {/* Verification status */}
                        <div className="verification-result">
                          <span className="field-label">
                            VERIFICATION STATUS
                          </span>

                          <div
                            className={`verification-badge ${getVerificationClass(
                              vulnerability.verification_status
                            )}`}
                          >
                            {formatVerificationStatus(
                              vulnerability.verification_status
                            )}
                          </div>

                          {vulnerability.verification_reason && (
                            <p>
                              {
                                vulnerability.verification_reason
                              }
                            </p>
                          )}
                        </div>

                        {/* Verification test */}
                        {vulnerability.verification_test && (
                          <div className="code-result">
                            <span className="field-label">
                              VERIFICATION TEST
                            </span>

                            <pre>
                              {
                                vulnerability.verification_test
                              }
                            </pre>
                          </div>
                        )}

                        {/* Sandbox output */}
                        {vulnerability.sandbox_output && (
                          <div className="code-result sandbox-output">
                            <span className="field-label">
                              SANDBOX OUTPUT
                            </span>

                            <pre>
                              {
                                vulnerability.sandbox_output
                              }
                            </pre>
                          </div>
                        )}

                        {/* Sandbox error */}
                        {vulnerability.sandbox_error && (
                          <div className="code-result sandbox-error">
                            <span className="field-label">
                              SANDBOX ERROR
                            </span>

                            <pre>
                              {
                                vulnerability.sandbox_error
                              }
                            </pre>
                          </div>
                        )}

                        <div className="confidence">
                          Confidence:{" "}
                          <strong>
                            {vulnerability.confidence ||
                              "HIGH"}
                          </strong>
                        </div>
                      </article>
                    )
                  )}
                </div>
              )}
            </section>
          )}
        </main>
      )}

      {/* ======================================================
          SANDBOX
      ====================================================== */}

      {activeTab === "sandbox" && (
        <main className="page analyzer-page">
          <section className="analyzer-header">
            <div>
              <div className="eyebrow">
                SAFE PATCH VALIDATION
              </div>

              <h1>
                Sandbox Verifier
              </h1>

              <p>
                Execute Python code inside the isolated
                ShadowCode sandbox before merging
                security changes.
              </p>
            </div>

            <div className="analyzer-badge">
              <span className="status-dot online"></span>
              API /sandbox/verify
            </div>
          </section>

          <section className="editor-card">
            <div className="editor-toolbar">
              <div className="window-controls">
                <span></span>
                <span></span>
                <span></span>
              </div>

              <div className="file-name">
                sandbox_test.py
              </div>

              <button
                type="button"
                className="demo-button"
                onClick={() => {
                  console.log("LOAD TEST CLICKED");

                  setSandboxCode(
                    'print("ShadowCode Sandbox OK")'
                  );
                  setSandboxResult(null);
                  setSandboxError("");
                }}
              >
                Load Test
              </button>
            </div>

            <div className="editor">
              <div className="line-numbers">
                {Array.from(
                  {
                    length: Math.max(
                      sandboxCode.split("\n").length,
                      12
                    ),
                  },
                  (_, i) => (
                    <span key={i}>
                      {i + 1}
                    </span>
                  )
                )}
              </div>

              <textarea
                value={sandboxCode}
                onChange={(e) => {
                  setSandboxCode(e.target.value);
                  setSandboxError("");
                  setSandboxResult(null);
                }}
                spellCheck="false"
                placeholder="Enter Python code to verify in the sandbox..."
              />
            </div>

            <div className="editor-footer">
              <span>
                Python • Isolated Sandbox Execution
              </span>

              <span>
                {sandboxCode.length} characters
              </span>
            </div>
          </section>

          <div className="analyze-row">
            <button
              className="primary-button analyze-button"
              onClick={verifySandbox}
              disabled={
                sandboxLoading ||
                !sandboxCode.trim()
              }
            >
              {sandboxLoading ? (
                <>
                  <span className="spinner"></span>
                  Verifying...
                </>
              ) : (
                <>
                  🧪 Start Verification
                  <span>→</span>
                </>
              )}
            </button>
          </div>

          {sandboxError && (
            <div className="error-box">
              ⚠ {sandboxError}
            </div>
          )}

          {sandboxResult && (
            <section className="results-section">
              <div className="results-summary">
                <div>
                  <div className="eyebrow">
                    SANDBOX EXECUTION COMPLETE
                  </div>

                  <h2>
                    Verification Result
                  </h2>
                </div>

                <div
                  className={`verification-badge ${getVerificationClass(
                    sandboxResult.status
                  )}`}
                >
                  {formatVerificationStatus(
                    sandboxResult.status
                  )}
                </div>
              </div>

              <div className="finding-card">
                <div className="finding-grid">
                  <div>
                    <span className="field-label">
                      STATUS
                    </span>

                    <p>
                      {sandboxResult.status ||
                        "UNKNOWN"}
                    </p>
                  </div>

                  <div>
                    <span className="field-label">
                      EXIT CODE
                    </span>

                    <p>
                      {sandboxResult.exit_code ??
                        "N/A"}
                    </p>
                  </div>
                </div>

                {sandboxResult.output && (
                  <div className="code-result sandbox-output">
                    <span className="field-label">
                      OUTPUT
                    </span>

                    <pre>
                      {sandboxResult.output}
                    </pre>
                  </div>
                )}

                {sandboxResult.error && (
                  <div className="code-result sandbox-error">
                    <span className="field-label">
                      ERROR
                    </span>

                    <pre>
                      {sandboxResult.error}
                    </pre>
                  </div>
                )}
              </div>
            </section>
          )}
        </main>
      )}

         {/* ======================================================
       AI ASSISTANT
   ====================================================== */}

   {activeTab === "assistant" && (
      <main className="page assistant-page">

         {/* HEADER */}
         <section className="assistant-hero">
            <div className="assistant-hero-content">

               <div className="eyebrow">
                  SHADOWCODE INTELLIGENCE
               </div>

               <h1>
                  Your AI Security
                  <span> Copilot.</span>
               </h1>

               <p>
                  Analyze vulnerabilities, understand security risks,
                  review fixes and get practical secure-coding guidance
                  from ShadowCode AI.
               </p>

               <div className="assistant-status-row">
                  <div
                     className={`assistant-live-status ${
                        engineOnline ? "online" : "offline"
                     }`}
                  >
                     <span className="assistant-live-dot"></span>

                     <span>
                        {engineOnline
                           ? "Security engine online"
                           : "Security engine offline"}
                     </span>
                  </div>

                  <span className="assistant-api-label">
                     /chat
                  </span>
               </div>

            </div>

            <div className="assistant-hero-orbit">
               <div className="assistant-orbit-ring ring-one"></div>
               <div className="assistant-orbit-ring ring-two"></div>

               <div className="assistant-core">
                  <span>✦</span>
               </div>

               <div className="assistant-core-label">
                  <strong>SC</strong>
                  <span>AI ENGINE</span>
               </div>
            </div>
         </section>


         {/* MAIN CHAT */}
         <section className="assistant-workspace">

            <div className="assistant-chat-panel">

               {/* CHAT HEADER */}
               <header className="assistant-chat-header">

                  <div className="assistant-profile">

                     <div className="assistant-avatar">
                        ✦
                     </div>

                     <div>
                        <strong>ShadowCode AI</strong>

                        <span>
                           Security Intelligence Assistant
                        </span>
                     </div>

                  </div>

                  <div className="assistant-header-status">
                     <span
                        className={`assistant-live-dot ${
                           engineOnline ? "online" : "offline"
                        }`}
                     ></span>

                     {engineOnline ? "ONLINE" : "OFFLINE"}
                  </div>

               </header>


               {/* CHAT BODY */}
               <div className="assistant-chat-body">

                  {chatMessages.length === 0 && (
                     <div className="assistant-welcome">

                        <div className="assistant-welcome-icon">
                           ✦
                        </div>

                        <h2>
                           How can I help secure your code?
                        </h2>

                        <p>
                           Ask me about vulnerabilities, remediation,
                           secure coding or your ShadowCode scan results.
                        </p>

                        <div className="assistant-welcome-tags">
                           <span>SQL Injection</span>
                           <span>Path Traversal</span>
                           <span>Authentication</span>
                           <span>Secure Coding</span>
                        </div>

                     </div>
                  )}


                  {chatMessages.map((message, index) => (
                     <div
                        key={index}
                        className={`assistant-chat-message ${
                           message.role === "user"
                              ? "from-user"
                              : "from-ai"
                        }`}
                     >

                        {message.role !== "user" && (
                           <div className="assistant-message-avatar">
                              ✦
                           </div>
                        )}

                        <div className="assistant-message-content">

                           <div className="assistant-message-name">
                              {message.role === "user"
                                 ? "You"
                                 : "ShadowCode AI"}
                           </div>

                           <div className="assistant-message-bubble">
                              {message.content}
                           </div>

                        </div>

                     </div>
                  ))}


                  {chatLoading && (
                     <div className="assistant-chat-message from-ai">

                        <div className="assistant-message-avatar">
                           ✦
                        </div>

                        <div className="assistant-message-content">

                           <div className="assistant-message-name">
                              ShadowCode AI
                           </div>

                           <div className="assistant-thinking">

                              <span className="assistant-thinking-dot"></span>
                              <span className="assistant-thinking-dot"></span>
                              <span className="assistant-thinking-dot"></span>

                              <span>
                                 Analyzing...
                              </span>

                           </div>

                        </div>

                     </div>
                  )}

               </div>


               {/* INPUT */}
               <div className="assistant-input-wrapper">

                  <div className="assistant-input-box">

                     <textarea
                        value={chatInput}
                        onChange={(e) => {
                           setChatInput(e.target.value);
                           setChatError("");
                        }}
                        onKeyDown={(e) => {
                           if (
                              e.key === "Enter" &&
                              !e.shiftKey
                           ) {
                              e.preventDefault();
                              sendChat();
                           }
                        }}
                        placeholder="Ask ShadowCode anything about application security..."
                        disabled={chatLoading}
                        rows={2}
                     />

                     <button
                        className="assistant-send-button"
                        onClick={sendChat}
                        disabled={
                           chatLoading ||
                           !chatInput.trim()
                        }
                     >
                        {chatLoading ? (
                           <span className="assistant-send-spinner"></span>
                        ) : (
                           "↑"
                        )}
                     </button>

                  </div>

                  <div className="assistant-input-footer">

                     <span>
                        Enter to send · Shift + Enter for new line
                     </span>

                     <span>
                        AI-generated security guidance
                     </span>

                  </div>

               </div>

            </div>


            {/* SIDEBAR */}
            <aside className="assistant-sidebar">

               <div className="assistant-sidebar-heading">
                  <span>QUICK ACTIONS</span>
               </div>


               <button
                  className="assistant-action-card"
                  onClick={() => {
                     setChatInput(
                        "Explain SQL injection and how to prevent it."
                     );
                  }}
               >
                  <div className="assistant-action-icon danger">
                     !
                  </div>

                  <div>
                     <strong>
                        Explain a vulnerability
                     </strong>

                     <span>
                        Understand attack impact and prevention.
                     </span>
                  </div>

                  <b>→</b>
               </button>


               <button
                  className="assistant-action-card"
                  onClick={() => {
                     setChatInput(
                        "Give me secure Python coding practices for preventing common vulnerabilities."
                     );
                  }}
               >
                  <div className="assistant-action-icon secure">
                     ✓
                  </div>

                  <div>
                     <strong>
                        Secure coding
                     </strong>

                     <span>
                        Learn practical defensive coding patterns.
                     </span>
                  </div>

                  <b>→</b>
               </button>


               <button
                  className="assistant-action-card"
                  onClick={() => {
                     setChatInput(
                        "How should I verify that a security patch actually fixes a vulnerability?"
                     );
                  }}
               >
                  <div className="assistant-action-icon verify">
                     ◇
                  </div>

                  <div>
                     <strong>
                        Review a fix
                     </strong>

                     <span>
                        Validate whether a remediation is effective.
                     </span>
                  </div>

                  <b>→</b>
               </button>


               <div className="assistant-security-note">

                  <div className="assistant-security-note-icon">
                     ✓
                  </div>

                  <div>
                     <strong>
                        Security-first assistance
                     </strong>

                     <p>
                        ShadowCode AI is designed to provide
                        security-focused explanations and
                        remediation guidance.
                     </p>
                  </div>

               </div>

            </aside>

         </section>


         {chatError && (
            <div className="assistant-error">
               <span>⚠</span>
               {chatError}
            </div>
         )}

      </main>
   )}

      {/* ======================================================
          FOOTER
      ====================================================== */}

      <footer>
        <span>
          ShadowCode Security Platform
        </span>

        <span>
          AI • AST • Sandbox • DevSecOps
        </span>
      </footer>
    </div>
  );
}

export default App;