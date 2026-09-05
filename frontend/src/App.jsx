import { useState, useEffect } from "react";
import "./App.css";

// IMPORTANT:
// Replace this with the actual URL Vercel gave your backend.
// Example:
// const API = "https://shadowcode-backend-xxxxx.vercel.app";
const API = "chkeerthitej-4302s-projects/shadowcode-backend ";

const demoCode = `from flask import request
import sqlite3

user = request.args.get("user")

query = "SELECT * FROM users WHERE name = '" + user + "'"`;

function App() {
  const [activeTab, setActiveTab] = useState("overview");
  const [code, setCode] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [engineOnline, setEngineOnline] = useState(false);

  useEffect(() => {
    fetch(`${API}/health`)
      .then((res) => res.ok)
      .then((ok) => setEngineOnline(ok))
      .catch(() => setEngineOnline(false));
  }, []);

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
        },
        body: JSON.stringify({
          code: code,
        }),
      });

      if (!response.ok) {
        throw new Error(`Backend returned ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      setError(
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

  const goToAnalyzer = () => {
    setActiveTab("analyzer");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const findings = result?.vulnerabilities || [];

  return (
    <div className="app">
      {/* NAVBAR */}
      <header className="navbar">
        <div className="brand" onClick={() => setActiveTab("overview")}>
          <div className="brand-logo">◇</div>

          <div className="brand-text">
            <div className="brand-title">
              ShadowCode
              <span className="version">v1.0 DevSecOps</span>
            </div>

            <div className="brand-subtitle">
              AI-Powered Security Engine
            </div>
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={activeTab === "overview" ? "nav-tab active" : "nav-tab"}
            onClick={() => setActiveTab("overview")}
          >
            <span>◈</span>
            Overview
          </button>

          <button
            className={activeTab === "analyzer" ? "nav-tab active" : "nav-tab"}
            onClick={() => setActiveTab("analyzer")}
          >
            <span>&lt;/&gt;</span>
            Code Analyzer
          </button>

          <button
            className={activeTab === "repo" ? "nav-tab active" : "nav-tab"}
            onClick={() => setActiveTab("repo")}
          >
            <span>▣</span>
            Repo Scanner
          </button>

          <button
            className={
              activeTab === "sandbox" ? "nav-tab active" : "nav-tab"
            }
            onClick={() => setActiveTab("sandbox")}
          >
            <span>›_</span>
            Sandbox Verifier
          </button>

          <button
            className={
              activeTab === "assistant" ? "nav-tab active" : "nav-tab"
            }
            onClick={() => setActiveTab("assistant")}
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

          {engineOnline ? "Engine Online" : "Engine Offline"}
        </div>
      </header>

      {/* OVERVIEW */}
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
                ShadowCode combines AST analysis, AI-powered security
                detection, Docker sandbox execution, and Git repository
                scanning into one unified security platform.
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
                  onClick={() => setActiveTab("repo")}
                >
                  Scan Repository
                  <span>▣</span>
                </button>
              </div>
            </div>

            <div className="hero-card">
              <div className="hero-card-icon">◇</div>

              <h3>ShadowCode</h3>

              <p>Featherless.ai Powered</p>

              <div className="mini-status">
                <span
                  className={`status-dot ${
                    engineOnline ? "online" : "offline"
                  }`}
                ></span>

                {engineOnline ? "Engine Online" : "Engine Offline"}
              </div>
            </div>
          </section>

          <section className="feature-grid">
            <div className="feature-card">
              <div className="feature-icon">&lt;/&gt;</div>

              <h3>AST + AI Hybrid Analysis</h3>

              <p>
                Parses source code and combines structural analysis with
                AI-powered vulnerability evaluation.
              </p>

              <button onClick={goToAnalyzer}>
                Open Analyzer →
              </button>
            </div>

            <div className="feature-card">
              <div className="feature-icon">›_</div>

              <h3>Sandbox Patch Verification</h3>

              <p>
                Applies security patches safely, executes tests, and
                verifies changes before merge.
              </p>

              <button onClick={() => setActiveTab("sandbox")}>
                Open Sandbox →
              </button>
            </div>

            <div className="feature-card">
              <div className="feature-icon">◎</div>

              <h3>Featherless.ai Pipeline</h3>

              <p>
                AI inference pipeline for intelligent source-code
                security analysis and remediation.
              </p>

              <button onClick={() => setActiveTab("assistant")}>
                Open AI Assistant →
              </button>
            </div>
          </section>

          <section className="workflow">
            <div className="section-heading">
              <span className="eyebrow">SECURITY WORKFLOW</span>

              <h2>From Code to Secure Release</h2>

              <p>
                A multi-layer pipeline designed to detect, understand and
                verify security issues.
              </p>
            </div>

            <div className="workflow-grid">
              <div className="workflow-step">
                <div className="step-number">01</div>

                <h3>Analyze</h3>

                <p>
                  Parse source code and identify suspicious patterns.
                </p>
              </div>

              <div className="workflow-line">→</div>

              <div className="workflow-step">
                <div className="step-number">02</div>

                <h3>Detect</h3>

                <p>
                  Combine static analysis with AI security evaluation.
                </p>
              </div>

              <div className="workflow-line">→</div>

              <div className="workflow-step">
                <div className="step-number">03</div>

                <h3>Verify</h3>

                <p>
                  Safely validate security fixes before deployment.
                </p>
              </div>
            </div>
          </section>
        </main>
      )}

      {/* CODE ANALYZER */}
      {activeTab === "analyzer" && (
        <main className="page analyzer-page">
          <section className="analyzer-header">
            <div>
              <div className="eyebrow">
                CODE SECURITY ANALYZER
              </div>

              <h1>
                Find vulnerabilities before they ship.
              </h1>

              <p>
                Paste your source code and let ShadowCode perform a
                multi-layer security analysis.
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
                    <span key={i}>{i + 1}</span>
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
                  <strong>{findings.length}</strong>
                  <span>findings</span>
                </div>
              </div>

              {findings.length === 0 ? (
                <div className="safe-box">
                  <div className="safe-icon">✓</div>

                  <div>
                    <h3>
                      No vulnerabilities detected
                    </h3>

                    <p>
                      ShadowCode did not identify any security
                      issues in the submitted code.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="findings-list">
                  {findings.map(
                    (vulnerability, index) => (
                      <article
                        className="finding-card"
                        key={index}
                      >
                        <div className="finding-top">
                          <div>
                            <span className="finding-number">
                              FINDING #{index + 1}
                            </span>

                            <h3>
                              {vulnerability.name ||
                                vulnerability.title ||
                                "Security Vulnerability"}
                            </h3>
                          </div>

                          <span
                            className={`severity ${String(
                              vulnerability.severity ||
                                "medium"
                            ).toLowerCase()}`}
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

      {/* REPO SCANNER */}
      {activeTab === "repo" && (
        <main className="page placeholder-page">
          <div className="placeholder-card">
            <div className="placeholder-icon">
              ▣
            </div>

            <div className="eyebrow">
              REPOSITORY SECURITY
            </div>

            <h1>
              Repository Scanner
            </h1>

            <p>
              Scan an entire Git repository for security
              vulnerabilities across multiple source files.
            </p>

            <div className="repo-input">
              <span>
                https://github.com/your-project/repository
              </span>
            </div>

            <button className="primary-button">
              Scan Repository →
            </button>

            <small>
              Repository scanning interface connected to the
              ShadowCode security workflow.
            </small>
          </div>
        </main>
      )}

      {/* SANDBOX */}
      {activeTab === "sandbox" && (
        <main className="page placeholder-page">
          <div className="placeholder-card">
            <div className="placeholder-icon">
              ›_
            </div>

            <div className="eyebrow">
              SAFE PATCH VALIDATION
            </div>

            <h1>
              Sandbox Verifier
            </h1>

            <p>
              Verify security patches inside an isolated execution
              environment before merging changes.
            </p>

            <div className="sandbox-status">
              <span className="status-dot"></span>
              Sandbox Ready
            </div>

            <button className="primary-button">
              Start Verification →
            </button>
          </div>
        </main>
      )}

      {/* AI ASSISTANT */}
      {activeTab === "assistant" && (
        <main className="page placeholder-page">
          <div className="placeholder-card assistant-card">
            <div className="placeholder-icon">
              ✦
            </div>

            <div className="eyebrow">
              AI SECURITY ASSISTANT
            </div>

            <h1>
              Ask ShadowCode
            </h1>

            <p>
              Get AI-powered explanations, remediation guidance and
              secure coding recommendations.
            </p>

            <div className="chat-box">
              <div className="assistant-message">
                <strong>
                  ShadowCode AI
                </strong>

                <span>
                  Paste code in the Code Analyzer and I can help
                  explain security findings and recommended fixes.
                </span>
              </div>
            </div>

            <button
              className="primary-button"
              onClick={goToAnalyzer}
            >
              Analyze Code →
            </button>
          </div>
        </main>
      )}

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