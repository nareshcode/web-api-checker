import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Typography,
  Box,
  Button,
  Alert,
  CircularProgress,
  Paper,
  Chip,
  IconButton,
  Divider,
  Grid,
  Card,
  CardContent,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  Download as DownloadIcon,
  Share as ShareIcon,
  GetApp as ExportIcon,
  Security as SecurityIcon,
  Schedule as TimeIcon,
  Assessment as AssessmentIcon,
} from '@mui/icons-material';
import ReactMarkdown from 'react-markdown';
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomOneDark } from 'react-syntax-highlighter/dist/esm/styles/hljs';
import javascript from 'react-syntax-highlighter/dist/esm/languages/hljs/javascript';
import bash from 'react-syntax-highlighter/dist/esm/languages/hljs/bash';
import { scanAPI } from '../utils/apiClient';

// Register languages
SyntaxHighlighter.registerLanguage('javascript', javascript);
SyntaxHighlighter.registerLanguage('bash', bash);

interface ReportData {
  scan_id: string;
  report_content: string;
  findings: any;
  start_time: string;
  end_time: string;
  duration: number;
}

const ReportDetail: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchReport = async () => {
      if (!scanId) {
        setError('No scan ID provided');
        setLoading(false);
        return;
      }

      try {
        const response = await scanAPI.getReport(scanId);
        setReport(response.data);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to load report');
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [scanId]);

  const handleBack = () => {
    navigate('/history');
  };

  const handleDownload = () => {
    if (!report) return;

    const blob = new Blob([report.report_content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${scanId}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportPDF = () => {
    // This would require a PDF generation library
    alert('PDF export coming soon!');
  };

  const formatDuration = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.floor(seconds % 60);
    return `${minutes}m ${remainingSeconds}s`;
  };

  // Enhanced markdown components for professional report display
  const components = {
    code({ node, inline, className, children, ...props }: any) {
      const match = /language-(\w+)/.exec(className || '');
      return !inline && match ? (
        <SyntaxHighlighter
          style={atomOneDark}
          language={match[1]}
          PreTag="div"
          customStyle={{
            borderRadius: '12px',
            fontSize: '14px',
            padding: '20px',
            margin: '16px 0',
            backgroundColor: '#1e1e1e',
          }}
          {...props}
        >
          {String(children).replace(/\n$/, '')}
        </SyntaxHighlighter>
      ) : (
        <code 
          className={className} 
          style={{
            backgroundColor: '#f5f5f5',
            padding: '2px 6px',
            borderRadius: '4px',
            fontSize: '0.9em',
            fontFamily: 'Monaco, Consolas, monospace'
          }}
          {...props}
        >
          {children}
        </code>
      );
    },
    h1: ({ children }: any) => (
      <Box sx={{ mb: 4, mt: 6 }}>
        <Typography 
          variant="h3" 
          component="h1" 
          sx={{ 
            fontWeight: 'bold',
            color: 'primary.main',
            borderBottom: '3px solid',
            borderColor: 'primary.main',
            pb: 2
          }}
        >
          {children}
        </Typography>
      </Box>
    ),
    h2: ({ children }: any) => (
      <Box sx={{ mt: 5, mb: 3 }}>
        <Typography 
          variant="h4" 
          component="h2" 
          sx={{ 
            fontWeight: 'bold',
            color: 'text.primary',
            display: 'flex',
            alignItems: 'center',
            gap: 1
          }}
        >
          {children}
        </Typography>
        <Divider sx={{ mt: 1, mb: 2 }} />
      </Box>
    ),
    h3: ({ children }: any) => (
      <Typography 
        variant="h5" 
        component="h3" 
        sx={{ 
          mt: 4, 
          mb: 2, 
          fontWeight: 'bold',
          color: 'text.primary'
        }}
      >
        {children}
      </Typography>
    ),
    p: ({ children }: any) => (
      <Typography 
        variant="body1" 
        paragraph 
        sx={{ 
          lineHeight: 1.7,
          mb: 2,
          fontSize: '1rem'
        }}
      >
        {children}
      </Typography>
    ),
    table: ({ children }: any) => (
      <Box sx={{ mb: 3, overflow: 'auto' }}>
        <Paper elevation={2} sx={{ borderRadius: 2 }}>
          <Box
            component="table"
            sx={{
              width: '100%',
              borderCollapse: 'collapse',
              '& th': {
                backgroundColor: 'primary.main',
                color: 'white',
                fontWeight: 'bold',
                padding: '16px',
                textAlign: 'left',
                fontSize: '0.95rem'
              },
              '& td': {
                padding: '16px',
                borderBottom: '1px solid #e0e0e0',
                fontSize: '0.9rem',
                lineHeight: 1.6
              },
              '& tr:nth-of-type(even) td': {
                backgroundColor: '#fafafa'
              },
              '& tr:hover td': {
                backgroundColor: '#f0f0f0'
              }
            }}
          >
            {children}
          </Box>
        </Paper>
      </Box>
    ),
    ul: ({ children }: any) => (
      <Box 
        component="ul" 
        sx={{ 
          pl: 3, 
          mb: 3,
          '& li': {
            mb: 1,
            lineHeight: 1.6
          }
        }}
      >
        {children}
      </Box>
    ),
    li: ({ children }: any) => (
      <Typography component="li" variant="body1" sx={{ mb: 1 }}>
        {children}
      </Typography>
    ),
    hr: () => <Divider sx={{ my: 4 }} />,
    blockquote: ({ children }: any) => (
      <Paper
        elevation={1}
        sx={{
          p: 3,
          bgcolor: 'grey.50',
          borderLeft: 6,
          borderColor: 'primary.main',
          my: 3,
          borderRadius: 2
        }}
      >
        {children}
      </Paper>
    ),
    details: ({ children }: any) => (
      <Paper
        elevation={1}
        sx={{
          p: 2,
          mb: 3,
          backgroundColor: '#f8f9fa',
          borderRadius: 2,
          border: '1px solid #e9ecef'
        }}
      >
        {children}
      </Paper>
    ),
    summary: ({ children }: any) => (
      <Typography
        component="summary"
        sx={{
          fontWeight: 'bold',
          cursor: 'pointer',
          padding: 1,
          '&:hover': {
            backgroundColor: '#e9ecef'
          }
        }}
      >
        {children}
      </Typography>
    ),
    strong: ({ children }: any) => (
      <Box component="strong" sx={{ fontWeight: 'bold', color: 'text.primary' }}>
        {children}
      </Box>
    )
  };

  // Calculate security metrics from findings
  const getSecurityMetrics = () => {
    if (!report?.findings?.api) return null;
    
    const findings = report.findings.api;
    let critical = 0, high = 0, medium = 0, low = 0;
    
    // Count vulnerabilities by type
    const criticalTypes = ['sql_injection', 'command_injection', 'xxe', 'ssrf'];
    const highTypes = ['xss', 'nosql_injection', 'ldap_injection', 'path_traversal'];
    
    criticalTypes.forEach(type => {
      if (findings[type] && Array.isArray(findings[type])) {
        critical += findings[type].length;
      }
    });
    
    highTypes.forEach(type => {
      if (findings[type] && Array.isArray(findings[type])) {
        high += findings[type].length;
      }
    });
    
    // Count security header issues
    if (findings.security_headers) {
      Object.values(findings.security_headers).forEach((headers: any) => {
        if (headers && typeof headers === 'object') {
          Object.values(headers).forEach((value) => {
            if (value === null) medium++;
          });
        }
      });
    }
    
    const total = critical + high + medium + low;
    const score = Math.max(0, 100 - (critical * 40 + high * 20 + medium * 10 + low * 5));
    
    return { critical, high, medium, low, total, score };
  };

  const metrics = getSecurityMetrics();

  if (loading) {
    return (
      <Container maxWidth="lg">
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress size={60} />
        </Box>
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg">
        <Alert severity="error" sx={{ mt: 4 }}>
          {error}
        </Alert>
        <Box sx={{ mt: 2 }}>
          <Button startIcon={<BackIcon />} onClick={handleBack}>
            Back to History
          </Button>
        </Box>
      </Container>
    );
  }

  if (!report) {
    return (
      <Container maxWidth="lg">
        <Alert severity="warning" sx={{ mt: 4 }}>
          Report not found
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      {/* Enhanced Header Section */}
      <Paper elevation={3} sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
          <Box>
            <Button
              startIcon={<BackIcon />}
              onClick={handleBack}
              sx={{ mb: 2 }}
              variant="outlined"
            >
              Back to History
            </Button>
            <Typography variant="h3" component="h1" gutterBottom sx={{ fontWeight: 'bold' }}>
              🔒 Security Assessment Report
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <IconButton
              onClick={handleDownload}
              color="primary"
              title="Download Markdown"
              sx={{ 
                backgroundColor: 'primary.light',
                color: 'white',
                '&:hover': { backgroundColor: 'primary.main' }
              }}
            >
              <DownloadIcon />
            </IconButton>
            <IconButton
              onClick={handleExportPDF}
              color="primary"
              title="Export PDF"
              sx={{ 
                backgroundColor: 'secondary.light',
                color: 'white',
                '&:hover': { backgroundColor: 'secondary.main' }
              }}
            >
              <ExportIcon />
            </IconButton>
          </Box>
        </Box>

        {/* Metrics Cards */}
        {metrics && (
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={3}>
              <Card elevation={2}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <SecurityIcon color="primary" sx={{ fontSize: 40, mb: 1 }} />
                  <Typography variant="h4" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
                    {metrics.score}/100
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Security Score
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card elevation={2}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <AssessmentIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
                  <Typography variant="h4" sx={{ fontWeight: 'bold', color: 'error.main' }}>
                    {metrics.total}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Issues
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card elevation={2}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <TimeIcon color="info" sx={{ fontSize: 40, mb: 1 }} />
                  <Typography variant="h4" sx={{ fontWeight: 'bold', color: 'info.main' }}>
                    {formatDuration(report.duration)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Scan Duration
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card elevation={2}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1, mb: 1 }}>
                    <Chip label={`${metrics.critical}🔴`} size="small" color="error" />
                    <Chip label={`${metrics.high}🟠`} size="small" color="warning" />
                    <Chip label={`${metrics.medium}🟡`} size="small" color="info" />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Risk Breakdown
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        )}

        {/* Report Metadata */}
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <Chip 
            label={`Scan ID: ${scanId?.slice(0, 8)}...`} 
            variant="outlined" 
            size="medium"
            icon={<SecurityIcon />}
          />
          <Chip 
            label={`Completed: ${new Date(report.end_time).toLocaleString()}`} 
            variant="outlined" 
            size="medium"
            icon={<TimeIcon />}
          />
        </Box>
      </Paper>

      {/* Report Content */}
      <Paper 
        elevation={2} 
        sx={{ 
          p: 5, 
          minHeight: 600,
          borderRadius: 3,
          backgroundColor: '#ffffff'
        }}
      >
        <ReactMarkdown components={components}>
          {report.report_content}
        </ReactMarkdown>
      </Paper>
    </Container>
  );
};

export default ReportDetail; 