/**
 * Complete Scan Page Component
 * Shows how to integrate with the new specialized agent architecture
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  LinearProgress,
  TextField,
  Typography,
  Grid,
  Chip,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow
} from '@mui/material';

// API configuration
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8001';

// API functions
const startScan = async (target) => {
  const response = await fetch(`${API_URL}/scans/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target })
  });
  if (!response.ok) throw new Error('Failed to start scan');
  return response.json();
};

const getScanStatus = async (jobId) => {
  const response = await fetch(`${API_URL}/scans/${jobId}/status`);
  if (!response.ok) throw new Error('Failed to get status');
  return response.json();
};

const finalizeScan = async (jobId) => {
  const response = await fetch(`${API_URL}/scans/${jobId}/finalize`, {
    method: 'POST'
  });
  if (!response.ok) throw new Error('Failed to finalize');
  return response.json();
};

// Severity colors
const SEVERITY_COLORS = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#388e3c',
  info: '#1976d2'
};

function ScanPage() {
  const [target, setTarget] = useState('');
  const [scanning, setScanning] = useState(false);
  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState(null);
  const [finalResults, setFinalResults] = useState(null);
  const [error, setError] = useState(null);

  // Start scan handler
  const handleStartScan = async (e) => {
    e.preventDefault();
    setError(null);
    setFinalResults(null);
    setStatus(null);

    try {
      setScanning(true);
      const response = await startScan(target);
      setJobId(response.job_id);
    } catch (err) {
      setError(err.message);
      setScanning(false);
    }
  };

  // Poll for status updates
  useEffect(() => {
    if (!jobId || !scanning) return;

    const pollInterval = setInterval(async () => {
      try {
        const currentStatus = await getScanStatus(jobId);
        setStatus(currentStatus);

        // Check if scan is complete
        const queueEmpty =
          currentStatus.queue_status.in_progress_count === 0 &&
          Object.values(currentStatus.queue_status.pending_by_type || {})
            .reduce((sum, count) => sum + count, 0) === 0;

        if (queueEmpty && currentStatus.status === 'running') {
          // Scan is done, finalize it
          clearInterval(pollInterval);
          const finalReport = await finalizeScan(jobId);
          setFinalResults(finalReport);
          setScanning(false);
        }
      } catch (err) {
        console.error('Status poll failed:', err);
        setError(err.message);
      }
    }, 2000); // Poll every 2 seconds

    return () => clearInterval(pollInterval);
  }, [jobId, scanning]);

  // Calculate progress percentage
  const getProgress = () => {
    if (!status) return 0;
    const { total_added, total_completed } = status.queue_status;
    return total_added > 0 ? (total_completed / total_added) * 100 : 0;
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Security Scanner - Specialized Agent Architecture
      </Typography>

      {/* Scan Form */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <form onSubmit={handleStartScan}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={8}>
                <TextField
                  fullWidth
                  label="Target Domain or URL"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="example.com or https://example.com"
                  disabled={scanning}
                  required
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Button
                  fullWidth
                  variant="contained"
                  color="primary"
                  type="submit"
                  disabled={scanning || !target}
                  startIcon={scanning && <CircularProgress size={20} />}
                >
                  {scanning ? 'Scanning...' : 'Start Scan'}
                </Button>
              </Grid>
            </Grid>
          </form>
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Live Status */}
      {scanning && status && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Scan Progress
            </Typography>

            <LinearProgress
              variant="determinate"
              value={getProgress()}
              sx={{ mb: 2, height: 10, borderRadius: 5 }}
            />

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" color="text.secondary">
                  Job ID: {jobId}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Duration: {status.execution_time_seconds?.toFixed(1)}s
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Tests: {status.queue_status.total_completed} / {status.queue_status.total_added}
                </Typography>
              </Grid>

              <Grid item xs={12} md={6}>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Chip
                    label={`${status.findings.total} Findings`}
                    color="primary"
                    size="small"
                  />
                  <Chip
                    label={`${status.queue_status.in_progress_count} In Progress`}
                    color="info"
                    size="small"
                  />
                  <Chip
                    label={`${status.queue_status.duplicates_prevented} Duplicates Prevented`}
                    color="success"
                    size="small"
                  />
                  <Chip
                    label={`${status.queue_status.efficiency?.toFixed(0)}% Efficient`}
                    color="warning"
                    size="small"
                  />
                </Box>
              </Grid>
            </Grid>

            {/* Live Findings Summary */}
            {status.findings.total > 0 && (
              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Findings by Severity
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {Object.entries(status.findings.by_severity || {}).map(([severity, count]) => (
                    <Chip
                      key={severity}
                      label={`${severity}: ${count}`}
                      size="small"
                      sx={{
                        backgroundColor: SEVERITY_COLORS[severity],
                        color: 'white'
                      }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {/* Agent Activity */}
            {status.findings.by_agent_type && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Findings by Agent Type
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {Object.entries(status.findings.by_agent_type).map(([type, count]) => (
                    <Chip
                      key={type}
                      label={`${type}: ${count}`}
                      variant="outlined"
                      size="small"
                    />
                  ))}
                </Box>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {/* Final Results */}
      {finalResults && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Scan Complete - Final Results
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h4" color="primary">
                      {finalResults.findings.total}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total Findings
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} md={4}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h4" color="success.main">
                      {finalResults.efficiency_metrics?.duplicates_prevented || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Duplicates Prevented
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} md={4}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h4" color="info.main">
                      {finalResults.execution_time_seconds?.toFixed(1)}s
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Execution Time
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            {/* Findings Table */}
            {finalResults.findings_details && finalResults.findings_details.length > 0 && (
              <Box>
                <Typography variant="subtitle1" gutterBottom>
                  Security Findings
                </Typography>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Severity</TableCell>
                      <TableCell>Title</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Agent</TableCell>
                      <TableCell>Discovered</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {finalResults.findings_details.map((finding, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Chip
                            label={finding.severity}
                            size="small"
                            sx={{
                              backgroundColor: SEVERITY_COLORS[finding.severity],
                              color: 'white'
                            }}
                          />
                        </TableCell>
                        <TableCell>{finding.title}</TableCell>
                        <TableCell>{finding.type}</TableCell>
                        <TableCell>{finding.agent_type}</TableCell>
                        <TableCell>
                          {new Date(finding.discovered_at).toLocaleTimeString()}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            )}

            {/* Efficiency Banner */}
            <Alert severity="success" sx={{ mt: 3 }}>
              <Typography variant="subtitle2">
                🚀 Specialized Agent Architecture Benefits
              </Typography>
              <Typography variant="body2">
                ✅ {finalResults.efficiency_metrics?.efficiency_percentage?.toFixed(0)}% efficiency
                <br />
                ✅ Zero duplicate testing across {finalResults.agents?.total} agents
                <br />
                ✅ Parallel execution across specialized domains
              </Typography>
            </Alert>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}

export default ScanPage;
