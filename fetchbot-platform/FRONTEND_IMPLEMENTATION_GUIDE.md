# Frontend Implementation Guide for Detailed Security Findings

## What Changed in the Backend

The API now returns **complete technical evidence** for every security finding. Here's what you'll receive:

### Enhanced API Response Structure

**GET /scan/{job_id}** now returns:

```json
{
  "job_id": "abc-123",
  "status": "completed",
  "target": "https://example.com",
  "findings": [
    {
      "id": "finding-uuid",
      "title": "Missing: Content-Security-Policy",
      "severity": "high",
      "type": "missing_header",
      "description": "CSP not implemented",
      "url": "https://example.com",

      // NEW: Complete technical evidence
      "evidence": {
        "http_method": "GET",
        "status_code": 200,
        "response_headers": {
          "server": "nginx/1.18.0",
          "date": "Mon, 09 Nov 2025 10:30:00 GMT"
        },
        "missing_header": "Content-Security-Policy",
        "detection_method": "HTTP Header Analysis",
        "tool_used": "FetchBot/agent-001",
        "curl_equivalent": "curl -I https://example.com"
      },

      // NEW: Platform-specific remediation
      "remediation": {
        "fix": "Add CSP header to HTTP responses",
        "example": "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';",
        "implementation": {
          "nginx": "add_header Content-Security-Policy \"default-src 'self';\" always;",
          "apache": "Header always set Content-Security-Policy \"default-src 'self';\"",
          "express": "app.use(helmet.contentSecurityPolicy({directives: {defaultSrc: [\"'self'\"]}}));"
        },
        "references": [
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        ]
      },

      // NEW: Risk classification
      "cvss_score": 6.5,
      "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
      "owasp_category": "A05:2021 – Security Misconfiguration",
      "discovered_at": "2025-11-09T10:30:00Z",
      "discovered_by": "Dynamic Agent"
    }
  ]
}
```

## Frontend Components to Build

### 1. Enhanced Finding Card Component

Create `FindingCard.jsx`:

```jsx
import React, { useState } from 'react';
import './FindingCard.css';

function FindingCard({ finding }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [showRemediation, setShowRemediation] = useState(false);

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#3b82f6',
      info: '#6b7280'
    };
    return colors[severity] || colors.info;
  };

  const getCvssRating = (score) => {
    if (!score) return null;
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    return 'Low';
  };

  return (
    <div className="finding-card" style={{ borderLeftColor: getSeverityColor(finding.severity) }}>
      {/* Header */}
      <div className="finding-header">
        <div className="finding-title-section">
          <h3>{finding.title}</h3>
          <span className={`severity-badge severity-${finding.severity}`}>
            {finding.severity.toUpperCase()}
          </span>
          {finding.cvss_score && (
            <span className="cvss-badge">
              CVSS {finding.cvss_score} ({getCvssRating(finding.cvss_score)})
            </span>
          )}
        </div>
        <div className="finding-meta">
          {finding.type && <span className="type-badge">{finding.type}</span>}
          {finding.discovered_by && (
            <span className="discovered-by">Found by: {finding.discovered_by}</span>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="finding-tabs">
        <button
          className={activeTab === 'overview' ? 'active' : ''}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button
          className={activeTab === 'evidence' ? 'active' : ''}
          onClick={() => setActiveTab('evidence')}
        >
          Evidence
        </button>
        <button
          className={activeTab === 'remediation' ? 'active' : ''}
          onClick={() => setActiveTab('remediation')}
        >
          Remediation
        </button>
        <button
          className={activeTab === 'classification' ? 'active' : ''}
          onClick={() => setActiveTab('classification')}
        >
          Classification
        </button>
      </div>

      {/* Tab Content */}
      <div className="finding-content">
        {activeTab === 'overview' && (
          <div className="overview-tab">
            <p className="description">{finding.description}</p>
            {finding.url && (
              <div className="detail-row">
                <strong>Affected URL:</strong>
                <code>{finding.url}</code>
              </div>
            )}
            {finding.payload && (
              <div className="detail-row">
                <strong>Payload:</strong>
                <code>{finding.payload}</code>
              </div>
            )}
          </div>
        )}

        {activeTab === 'evidence' && finding.evidence && (
          <div className="evidence-tab">
            <h4>Technical Evidence</h4>

            {/* Step-by-step investigation */}
            <div className="evidence-steps">
              <div className="evidence-step">
                <div className="step-number">1</div>
                <div className="step-content">
                  <h5>Request Sent</h5>
                  <p>Method: <code>{finding.evidence.http_method || 'GET'}</code></p>
                  {finding.evidence.vulnerable_url && (
                    <p>URL: <code>{finding.evidence.vulnerable_url}</code></p>
                  )}
                  {finding.evidence.vulnerable_parameter && (
                    <p>Parameter: <code>{finding.evidence.vulnerable_parameter}</code></p>
                  )}
                  {finding.evidence.payload_used && (
                    <p>Payload: <code>{finding.evidence.payload_used}</code></p>
                  )}
                </div>
              </div>

              <div className="evidence-step">
                <div className="step-number">2</div>
                <div className="step-content">
                  <h5>Response Received</h5>
                  <p>Status: <code>{finding.evidence.status_code || finding.evidence.response_status}</code></p>
                  {finding.evidence.server && (
                    <p>Server: <code>{finding.evidence.server}</code></p>
                  )}
                  {finding.evidence.database_type && (
                    <p>Database: <code>{finding.evidence.database_type}</code></p>
                  )}
                </div>
              </div>

              <div className="evidence-step">
                <div className="step-number">3</div>
                <div className="step-content">
                  <h5>Detection Method</h5>
                  <p>{finding.evidence.detection_method}</p>
                  {finding.evidence.tool_used && (
                    <p>Tool: <code>{finding.evidence.tool_used}</code></p>
                  )}
                  {finding.evidence.sql_error_detected && (
                    <div className="error-box">
                      <strong>SQL Error:</strong>
                      <pre>{finding.evidence.sql_error_detected}</pre>
                    </div>
                  )}
                  {finding.evidence.payload_reflected && (
                    <p className="success-text">✓ Payload reflected in response</p>
                  )}
                </div>
              </div>

              <div className="evidence-step">
                <div className="step-number">4</div>
                <div className="step-content">
                  <h5>Reproduce</h5>
                  {finding.evidence.curl_equivalent && (
                    <div className="code-block">
                      <code>{finding.evidence.curl_equivalent}</code>
                      <button
                        className="copy-btn"
                        onClick={() => navigator.clipboard.writeText(finding.evidence.curl_equivalent)}
                      >
                        Copy
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Response headers if available */}
            {finding.evidence.response_headers && (
              <details className="headers-details">
                <summary>Response Headers ({Object.keys(finding.evidence.response_headers).length})</summary>
                <pre>{JSON.stringify(finding.evidence.response_headers, null, 2)}</pre>
              </details>
            )}
          </div>
        )}

        {activeTab === 'remediation' && finding.remediation && (
          <div className="remediation-tab">
            <h4>How to Fix</h4>
            <p className="fix-description">{finding.remediation.fix}</p>

            {finding.remediation.example && (
              <div className="example-section">
                <h5>Example Configuration</h5>
                <pre className="code-block">{finding.remediation.example}</pre>
              </div>
            )}

            {finding.remediation.implementation && (
              <div className="implementation-section">
                <h5>Platform-Specific Implementation</h5>
                {Object.entries(finding.remediation.implementation).map(([platform, code]) => (
                  <div key={platform} className="platform-code">
                    <h6>{platform.toUpperCase()}</h6>
                    <pre className="code-block">
                      {code}
                      <button
                        className="copy-btn"
                        onClick={() => navigator.clipboard.writeText(code)}
                      >
                        Copy
                      </button>
                    </pre>
                  </div>
                ))}
              </div>
            )}

            {finding.remediation.additional_steps && (
              <div className="additional-steps">
                <h5>Additional Security Measures</h5>
                <ul>
                  {finding.remediation.additional_steps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>
            )}

            {finding.remediation.references && finding.remediation.references.length > 0 && (
              <div className="references">
                <h5>References</h5>
                <ul>
                  {finding.remediation.references.map((ref, idx) => (
                    <li key={idx}>
                      <a href={ref} target="_blank" rel="noopener noreferrer">
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {activeTab === 'classification' && (
          <div className="classification-tab">
            <div className="classification-grid">
              {finding.cvss_score && (
                <div className="classification-item">
                  <h5>CVSS Score</h5>
                  <div className="cvss-score-large">{finding.cvss_score}</div>
                  <p>{getCvssRating(finding.cvss_score)}</p>
                </div>
              )}

              {finding.cwe && (
                <div className="classification-item">
                  <h5>CWE</h5>
                  <p>{finding.cwe}</p>
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${finding.cwe.match(/\d+/)?.[0]}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    View CWE Details →
                  </a>
                </div>
              )}

              {finding.owasp_category && (
                <div className="classification-item">
                  <h5>OWASP Top 10</h5>
                  <p>{finding.owasp_category}</p>
                </div>
              )}

              {finding.discovered_at && (
                <div className="classification-item">
                  <h5>Discovered</h5>
                  <p>{new Date(finding.discovered_at).toLocaleString()}</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default FindingCard;
```

### 2. Scan Results Page Component

Create `ScanResultsPage.jsx`:

```jsx
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import FindingCard from './FindingCard';
import './ScanResults.css';

function ScanResultsPage() {
  const { jobId } = useParams();
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('all');

  useEffect(() => {
    fetchScanResults();
  }, [jobId]);

  const fetchScanResults = async () => {
    try {
      const response = await fetch(`http://localhost:8000/scan/${jobId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });

      if (!response.ok) throw new Error('Failed to fetch scan results');

      const data = await response.json();
      setScanData(data);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  if (loading) return <div className="loading">Loading scan results...</div>;
  if (error) return <div className="error">Error: {error}</div>;
  if (!scanData) return null;

  const filteredFindings = severityFilter === 'all'
    ? scanData.findings
    : scanData.findings.filter(f => f.severity === severityFilter);

  const severityCounts = {
    critical: scanData.findings.filter(f => f.severity === 'critical').length,
    high: scanData.findings.filter(f => f.severity === 'high').length,
    medium: scanData.findings.filter(f => f.severity === 'medium').length,
    low: scanData.findings.filter(f => f.severity === 'low').length,
    info: scanData.findings.filter(f => f.severity === 'info').length,
  };

  return (
    <div className="scan-results-page">
      {/* Header */}
      <div className="results-header">
        <h1>Security Scan Results</h1>
        <div className="scan-meta">
          <span>Target: <strong>{scanData.target}</strong></span>
          <span>Status: <strong>{scanData.status}</strong></span>
          <span>Total Findings: <strong>{scanData.total_findings}</strong></span>
        </div>
      </div>

      {/* Severity Summary */}
      <div className="severity-summary">
        <button
          className={severityFilter === 'all' ? 'active' : ''}
          onClick={() => setSeverityFilter('all')}
        >
          All ({scanData.findings.length})
        </button>
        <button
          className={`severity-critical ${severityFilter === 'critical' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('critical')}
        >
          Critical ({severityCounts.critical})
        </button>
        <button
          className={`severity-high ${severityFilter === 'high' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('high')}
        >
          High ({severityCounts.high})
        </button>
        <button
          className={`severity-medium ${severityFilter === 'medium' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('medium')}
        >
          Medium ({severityCounts.medium})
        </button>
        <button
          className={`severity-low ${severityFilter === 'low' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('low')}
        >
          Low ({severityCounts.low})
        </button>
        <button
          className={`severity-info ${severityFilter === 'info' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('info')}
        >
          Info ({severityCounts.info})
        </button>
      </div>

      {/* Findings List */}
      <div className="findings-list">
        {filteredFindings.length === 0 ? (
          <div className="no-findings">
            No {severityFilter !== 'all' ? severityFilter : ''} findings found
          </div>
        ) : (
          filteredFindings.map(finding => (
            <FindingCard key={finding.id} finding={finding} />
          ))
        )}
      </div>
    </div>
  );
}

export default ScanResultsPage;
```

### 3. Styling (FindingCard.css)

Create `FindingCard.css`:

```css
.finding-card {
  background: white;
  border-radius: 8px;
  border-left: 4px solid #dc2626;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  margin-bottom: 20px;
  overflow: hidden;
}

.finding-header {
  padding: 20px;
  border-bottom: 1px solid #e5e7eb;
}

.finding-title-section {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.finding-title-section h3 {
  margin: 0;
  font-size: 18px;
  color: #111827;
}

.severity-badge {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
}

.severity-critical { background: #fee2e2; color: #dc2626; }
.severity-high { background: #ffedd5; color: #ea580c; }
.severity-medium { background: #fef3c7; color: #f59e0b; }
.severity-low { background: #dbeafe; color: #3b82f6; }
.severity-info { background: #f3f4f6; color: #6b7280; }

.cvss-badge {
  padding: 4px 12px;
  background: #f3f4f6;
  border-radius: 4px;
  font-size: 12px;
  color: #374151;
}

.finding-meta {
  display: flex;
  gap: 16px;
  font-size: 14px;
  color: #6b7280;
}

.type-badge {
  padding: 2px 8px;
  background: #f3f4f6;
  border-radius: 3px;
  font-family: monospace;
  font-size: 12px;
}

.finding-tabs {
  display: flex;
  background: #f9fafb;
  border-bottom: 1px solid #e5e7eb;
}

.finding-tabs button {
  flex: 1;
  padding: 12px 20px;
  border: none;
  background: transparent;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  color: #6b7280;
  transition: all 0.2s;
}

.finding-tabs button:hover {
  background: #f3f4f6;
}

.finding-tabs button.active {
  color: #2563eb;
  border-bottom: 2px solid #2563eb;
  background: white;
}

.finding-content {
  padding: 20px;
}

.description {
  color: #374151;
  line-height: 1.6;
  margin-bottom: 16px;
}

.detail-row {
  margin-bottom: 12px;
}

.detail-row strong {
  display: block;
  margin-bottom: 4px;
  color: #111827;
  font-size: 14px;
}

.detail-row code {
  display: block;
  padding: 8px 12px;
  background: #f3f4f6;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 13px;
  color: #374151;
  word-break: break-all;
}

/* Evidence Tab */
.evidence-steps {
  margin-top: 20px;
}

.evidence-step {
  display: flex;
  gap: 16px;
  margin-bottom: 24px;
}

.step-number {
  flex-shrink: 0;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: #2563eb;
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  font-size: 14px;
}

.step-content {
  flex: 1;
}

.step-content h5 {
  margin: 0 0 8px 0;
  color: #111827;
  font-size: 16px;
}

.step-content p {
  margin: 4px 0;
  color: #374151;
  font-size: 14px;
}

.step-content code {
  padding: 2px 6px;
  background: #f3f4f6;
  border-radius: 3px;
  font-family: monospace;
  font-size: 13px;
}

.error-box {
  margin-top: 8px;
  padding: 12px;
  background: #fee2e2;
  border-left: 3px solid #dc2626;
  border-radius: 4px;
}

.error-box strong {
  display: block;
  margin-bottom: 8px;
  color: #991b1b;
}

.error-box pre {
  margin: 0;
  font-family: monospace;
  font-size: 12px;
  color: #7f1d1d;
  white-space: pre-wrap;
}

.success-text {
  color: #059669 !important;
  font-weight: 500;
}

.code-block {
  position: relative;
  padding: 12px;
  background: #1e1e1e;
  border-radius: 6px;
  margin-top: 8px;
}

.code-block code {
  color: #d4d4d4;
  font-family: 'Courier New', monospace;
  font-size: 13px;
  display: block;
  overflow-x: auto;
}

.copy-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  padding: 4px 12px;
  background: #374151;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}

.copy-btn:hover {
  background: #4b5563;
}

.headers-details {
  margin-top: 16px;
  padding: 12px;
  background: #f9fafb;
  border-radius: 6px;
}

.headers-details summary {
  cursor: pointer;
  font-weight: 500;
  color: #374151;
}

.headers-details pre {
  margin-top: 12px;
  padding: 12px;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  font-size: 12px;
  overflow-x: auto;
}

/* Remediation Tab */
.remediation-tab h4 {
  margin: 0 0 16px 0;
  color: #111827;
}

.fix-description {
  color: #374151;
  line-height: 1.6;
  margin-bottom: 20px;
}

.example-section,
.implementation-section,
.additional-steps,
.references {
  margin-bottom: 24px;
}

.example-section h5,
.implementation-section h5,
.additional-steps h5,
.references h5 {
  margin: 0 0 12px 0;
  color: #111827;
  font-size: 16px;
}

.platform-code {
  margin-bottom: 16px;
}

.platform-code h6 {
  margin: 0 0 8px 0;
  color: #6b7280;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.additional-steps ul,
.references ul {
  list-style: none;
  padding: 0;
}

.additional-steps li {
  padding: 8px 0 8px 28px;
  position: relative;
  color: #374151;
}

.additional-steps li::before {
  content: "✓";
  position: absolute;
  left: 0;
  color: #059669;
  font-weight: bold;
}

.references li {
  margin-bottom: 8px;
}

.references a {
  color: #2563eb;
  text-decoration: none;
}

.references a:hover {
  text-decoration: underline;
}

/* Classification Tab */
.classification-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
}

.classification-item {
  padding: 20px;
  background: #f9fafb;
  border-radius: 8px;
}

.classification-item h5 {
  margin: 0 0 12px 0;
  color: #6b7280;
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.classification-item p {
  margin: 0;
  color: #111827;
  font-size: 15px;
}

.cvss-score-large {
  font-size: 48px;
  font-weight: bold;
  color: #dc2626;
  margin: 8px 0;
}

.classification-item a {
  color: #2563eb;
  text-decoration: none;
  font-size: 14px;
}

.classification-item a:hover {
  text-decoration: underline;
}
```

### 4. Usage Example

```jsx
// In your App.js or router configuration
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import ScanResultsPage from './components/ScanResultsPage';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/scan/:jobId" element={<ScanResultsPage />} />
      </Routes>
    </BrowserRouter>
  );
}
```

## Key Features of This Implementation

1. **4-Step Evidence Display** - Shows exactly WHERE and HOW the vulnerability was found
2. **Platform-Specific Remediation** - Copy-paste code for nginx, apache, express, etc.
3. **CVSS/CWE/OWASP Classification** - Industry-standard risk ratings
4. **Tabbed Interface** - Clean separation of concerns (overview, evidence, remediation, classification)
5. **Severity Filtering** - Filter findings by severity level
6. **Copy-to-Clipboard** - One-click copy for curl commands and code examples
7. **Responsive Design** - Works on mobile and desktop

## Testing the Integration

1. Start the API (migrations will run automatically)
2. Run a security scan
3. The API will return findings with complete evidence
4. Your React frontend will display the detailed findings with all tabs

All the backend work is done - you just need to build the frontend using this guide!
