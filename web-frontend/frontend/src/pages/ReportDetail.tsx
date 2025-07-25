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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  useTheme,
  useMediaQuery,
  Collapse,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Fab,
  Tooltip,

  Breadcrumbs,
  Link,
    Tab,
  Tabs,
  Drawer,
  Avatar,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  Download as DownloadIcon,

  Security as SecurityIcon,
  Schedule as TimeIcon,
  Assessment as AssessmentIcon,
  ExpandMore as ExpandMoreIcon,
  Shield as ShieldIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,

  Warning as WarningIcon,
  Error as ErrorIcon,
  BugReport as BugIcon,
  Code as CodeIcon,
  PlayArrow as RunIcon,
  MenuBook as WikiIcon,
  Share as ShareIcon,
  Print as PrintIcon,

  Speed as SpeedIcon,
  AccountBalance as BankIcon,
  VpnLock as VpnIcon,
  DataObject as DataIcon,
  Web as WebIcon,
  Settings as SettingsIcon,

  Category as CategoryIcon,
  Close as CloseIcon,
  KeyboardArrowRight as ArrowRightIcon,
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
  target_url: string;
  report_content: string;
  findings: any;
  start_time: string;
  end_time: string;
  duration: number;
}

interface SecurityMetrics {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  score: number;
  riskLevel: string;
  riskColor: string;
  issues: {
    critical: { name: string; details?: any }[];
    high: { name: string; details?: any }[];
    medium: { name: string; details?: any }[];
    low: { name: string; details?: any }[];
  };
}



interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

interface VulnerabilityDetailProps {
  severity: 'critical' | 'high' | 'medium' | 'low';
  issues: { name: string; details?: any }[];
  open: boolean;
  onClose: () => void;
}

interface BlockedRequest {
  payload: string;
  layer_type: string;
  block_reason: string;
  confidence: number;
  attack_type: string;
}

function CustomTabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

// Component to show vulnerability details in a drawer
function VulnerabilityDetailDrawer({ severity, issues, open, onClose }: VulnerabilityDetailProps) {
  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#1976d2';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  };

  const getSeverityIcon = (sev: string) => {
    switch (sev) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  };

  const formatVulnerabilityDetails = (details: any) => {
    if (Array.isArray(details)) {
      if (details.length === 0) return 'No specific details available';
      return details.map((item, index) => (
        <Box key={index} sx={{ mb: 1, p: 1, bgcolor: 'grey.50', borderRadius: 1 }}>
          {typeof item === 'string' ? item : JSON.stringify(item, null, 2)}
        </Box>
      ));
    } else if (typeof details === 'string') {
      if (details.includes('MISSING_SECURITY_HEADERS:')) {
        const headers = details.replace('MISSING_SECURITY_HEADERS: ', '').split(',').map(h => h.trim());
        return (
          <Box>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              The following security headers are missing:
            </Typography>
            <List dense>
              {headers.map((header, index) => (
                <ListItem key={index} sx={{ py: 0.5 }}>
                  <ListItemIcon sx={{ minWidth: 30 }}>
                    <WarningIcon color="warning" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={header} />
                </ListItem>
              ))}
            </List>
          </Box>
        );
      }
      return details;
    } else if (typeof details === 'object') {
      return (
        <SyntaxHighlighter
          language="json"
          style={atomOneDark}
          customStyle={{ borderRadius: '8px', fontSize: '12px', maxHeight: '200px' }}
        >
          {JSON.stringify(details, null, 2)}
        </SyntaxHighlighter>
      );
    }
    return 'No details available';
  };

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      sx={{
        '& .MuiDrawer-paper': {
          width: { xs: '100%', sm: '500px', md: '600px' },
          maxWidth: '90vw'
        }
      }}
    >
      <Box sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Avatar sx={{ bgcolor: getSeverityColor(severity), width: 40, height: 40 }}>
              {getSeverityIcon(severity)}
            </Avatar>
            <Box>
              <Typography variant="h5" sx={{ textTransform: 'capitalize', fontWeight: 'bold' }}>
                {severity} Severity Issues
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {issues.length} issue{issues.length !== 1 ? 's' : ''} found
              </Typography>
            </Box>
          </Box>
          <IconButton onClick={onClose} size="large">
            <CloseIcon />
          </IconButton>
        </Box>

        <Divider sx={{ mb: 3 }} />

        {issues.length === 0 ? (
          <Alert severity="info">
            <Typography variant="h6">No {severity} issues found</Typography>
            <Typography>This is great news! No vulnerabilities of this severity level were detected.</Typography>
          </Alert>
        ) : (
          <List>
            {issues.map((issue, index) => (
              <ListItem key={index} sx={{ mb: 2, p: 0 }}>
                <Card sx={{ width: '100%', border: `2px solid ${getSeverityColor(severity)}20` }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      <BugIcon color="primary" />
                      <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                        {issue.name}
                      </Typography>
                      <Chip
                        label={severity.toUpperCase()}
                        size="small"
                        sx={{
                          bgcolor: getSeverityColor(severity),
                          color: 'white',
                          fontWeight: 'bold'
                        }}
                      />
                    </Box>
                    
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Details:
                    </Typography>
                    
                    <Box sx={{ mt: 1 }}>
                      {formatVulnerabilityDetails(issue.details)}
                    </Box>

                    {/* Remediation suggestions based on vulnerability type */}
                    {issue.name.toLowerCase().includes('security header') && (
                      <Alert severity="info" sx={{ mt: 2 }}>
                        <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                          💡 Quick Fix:
                        </Typography>
                        <Typography variant="body2">
                          Add the missing security headers to your server configuration or reverse proxy.
                        </Typography>
                      </Alert>
                    )}

                    {issue.name.toLowerCase().includes('sql injection') && (
                      <Alert severity="error" sx={{ mt: 2 }}>
                        <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                          🚨 Critical Action Required:
                        </Typography>
                        <Typography variant="body2">
                          Immediately implement parameterized queries and input validation.
                        </Typography>
                      </Alert>
                    )}

                    {issue.name.toLowerCase().includes('xss') && (
                      <Alert severity="warning" sx={{ mt: 2 }}>
                        <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                          ⚠️ Important:
                        </Typography>
                        <Typography variant="body2">
                          Implement proper input sanitization and output encoding.
                        </Typography>
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              </ListItem>
            ))}
          </List>
        )}
      </Box>
    </Drawer>
  );
}

const ReportDetail: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');


  const [expandedSection, setExpandedSection] = useState<string | false>('overview');
  const [tabValue, setTabValue] = useState(0);
  const [vulnerabilityDrawer, setVulnerabilityDrawer] = useState<{
    open: boolean;
    severity: 'critical' | 'high' | 'medium' | 'low';
    issues: { name: string; details?: any }[];
  }>({
    open: false,
    severity: 'low',
    issues: []
  });

  const [aiRecommendations, setAiRecommendations] = useState<{
    loading: boolean;
    priority1: string;
    priority2: string;
    error?: string;
  }>({
    loading: false,
    priority1: '',
    priority2: ''
  });

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

  const handleWiki = () => {
    navigate('/wiki');
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

  const handleShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'Security Report',
          text: `Security scan report for scan ID: ${scanId}`,
          url: window.location.href,
        });
      } catch (err) {
        console.log('Share cancelled');
      }
    } else {
      // Fallback to copying link
      navigator.clipboard.writeText(window.location.href);
      // Could show a snackbar here
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const formatDuration = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.floor(seconds % 60);
    if (minutes > 0) {
      return `${minutes}m ${remainingSeconds}s`;
    }
    return `${remainingSeconds}s`;
  };

  // Calculate comprehensive security metrics using CVSS scores from data
  const getSecurityMetrics = (): SecurityMetrics => {
    if (!report?.findings?.api) {
      return {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
        score: 100,
        riskLevel: 'UNKNOWN',
        riskColor: 'grey',
        issues: { critical: [], high: [], medium: [], low: [] },
      };
    }
    
    const findings = report.findings.api;
    let critical = 0, high = 0, medium = 0, low = 0;
    const issues: SecurityMetrics['issues'] = { critical: [], high: [], medium: [], low: [] };
    
    // Handle new structure with vulnerabilities
    const vulnerabilities = findings.vulnerabilities || findings;
    
    // Handle severity-based structure (preferred - from actual scan data)
    if (vulnerabilities.critical && Array.isArray(vulnerabilities.critical)) {
      critical = vulnerabilities.critical.length;
      issues.critical.push(...vulnerabilities.critical.map((v: any) => ({ name: v.type || '', details: v })));
    }
    if (vulnerabilities.high && Array.isArray(vulnerabilities.high)) {
      high = vulnerabilities.high.length;
      issues.high.push(...vulnerabilities.high.map((v: any) => ({ name: v.type || '', details: v })));
    }
    if (vulnerabilities.medium && Array.isArray(vulnerabilities.medium)) {
      medium = vulnerabilities.medium.length;
      issues.medium.push(...vulnerabilities.medium.map((v: any) => ({ name: v.type || '', details: v })));
    }
    if (vulnerabilities.low && Array.isArray(vulnerabilities.low)) {
      low = vulnerabilities.low.length;
      issues.low.push(...vulnerabilities.low.map((v: any) => ({ name: v.type || '', details: v })));
    }
    
    // Handle legacy type-based structure only if severity-based structure is not available
    if (!vulnerabilities.critical && !vulnerabilities.high && !vulnerabilities.medium && !vulnerabilities.low) {
      // CVSS-based categorization using actual report generator categorization matrix
      const categorizeVulnerabilityType = (type: string): 'critical' | 'high' | 'medium' | 'low' => {
        // Critical vulnerabilities (CVSS >= 8.5)
        const criticalTypes = ['sql_injection', 'command_injection', 'xxe', 'ssrf', 'double_spending', 'race_conditions', 'https', 'open_endpoint'];
        // High vulnerabilities (CVSS 7.0-8.4)
        const highTypes = ['xss', 'nosql_injection', 'ldap_injection', 'path_traversal', 'auth_bypass', 'privilege_escalation', 'bola_attacks', 'transaction_manipulation', 'session_fixation', 'kyc_bypass', 'loan_abuse', 'webhook_abuse', 'open_redirects'];
        // Medium vulnerabilities (CVSS 4.0-6.9)
        const mediumTypes = ['security_headers', 'security_header', 'cors', 'rate_limiting', 'error_handling', 'metadata_leakage', 'verbose_errors', 'discount_abuse', 'micro_transactions', 'idempotency_check'];
        // Low vulnerabilities (CVSS < 4.0)
        const lowTypes = ['general', 'information_disclosure'];
        
        if (criticalTypes.includes(type)) return 'critical';
        if (highTypes.includes(type)) return 'high';
        if (mediumTypes.includes(type)) return 'medium';
        return 'low';
      };

      // Process all vulnerability types found in data
      Object.keys(vulnerabilities).forEach(type => {
        if (vulnerabilities[type] && Array.isArray(vulnerabilities[type]) && vulnerabilities[type].length > 0) {
          const severity = categorizeVulnerabilityType(type);
          const count = vulnerabilities[type].length;
          const name = type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          
          if (severity === 'critical') {
            critical += count;
            issues.critical.push({ name, details: vulnerabilities[type] });
          } else if (severity === 'high') {
            high += count;
            issues.high.push({ name, details: vulnerabilities[type] });
          } else if (severity === 'medium') {
            medium += count;
            issues.medium.push({ name, details: vulnerabilities[type] });
          } else {
            low += count;
            issues.low.push({ name, details: vulnerabilities[type] });
          }
        } else if (vulnerabilities[type] && typeof vulnerabilities[type] === 'string') {
          const severity = categorizeVulnerabilityType(type);
          
          // Handle string-based findings like security headers
          if (type === 'security_headers' && vulnerabilities[type].includes('MISSING_SECURITY_HEADERS:')) {
            const headersStr = vulnerabilities[type].replace('MISSING_SECURITY_HEADERS: ', '');
            const headers = headersStr.split(',').filter((h: string) => h.trim()).map((h: string) => h.trim());
            medium += headers.length;
            issues.medium.push({
              name: 'Missing Security Headers',
              details: headers
            });
          } else {
            const name = type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            if (severity === 'critical') {
              critical += 1;
              issues.critical.push({ name, details: vulnerabilities[type] });
            } else if (severity === 'high') {
              high += 1;
              issues.high.push({ name, details: vulnerabilities[type] });
            } else if (severity === 'medium') {
              medium += 1;
              issues.medium.push({ name, details: vulnerabilities[type] });
            } else {
              low += 1;
              issues.low.push({ name, details: vulnerabilities[type] });
            }
          }
        }
      });
    }
    
    const total = critical + high + medium + low;
    const score = Math.max(0, 100 - (critical * 40 + high * 20 + medium * 10 + low * 5));
    
    let riskLevel = 'EXCELLENT';
    let riskColor = 'success';
    
    if (score >= 90) {
      riskLevel = 'EXCELLENT';
      riskColor = 'success';
    } else if (score >= 75) {
      riskLevel = 'GOOD';
      riskColor = 'info';
    } else if (score >= 50) {
      riskLevel = 'MODERATE';
      riskColor = 'warning';
    } else {
      riskLevel = 'HIGH RISK';
      riskColor = 'error';
    }
    
    return { critical, high, medium, low, total, score, riskLevel, riskColor, issues };
  };



  // Get vulnerability breakdown by category using actual report generator categories
  const getVulnerabilityBreakdown = () => {
    if (!report?.findings?.api) return {};
    
    const findings = report.findings.api;
    const vulnerabilities = findings.vulnerabilities || findings;
    
    // Categories matching the exact categorization from report_generator.py
    const categories = {
      'Injection Attacks': ['sql_injection', 'command_injection', 'xss', 'xxe', 'ssrf', 'nosql_injection', 'ldap_injection'],
      'Banking Security': ['double_spending', 'race_conditions', 'transaction_manipulation', 'kyc_bypass', 'loan_abuse', 'discount_abuse', 'micro_transactions'],
      'Authentication & Authorization': ['auth_bypass', 'privilege_escalation', 'bola_attacks', 'session_fixation'],
      'Information Disclosure': ['metadata_leakage', 'verbose_errors', 'open_endpoint', 'information_disclosure', 'error_handling'],
      'Security Configuration': ['security_headers', 'security_header', 'cors', 'rate_limiting', 'idempotency_check'],
      'Path & Redirect Vulnerabilities': ['path_traversal', 'open_redirects'],
      'External Service Abuse': ['webhook_abuse']
    };
    
    const breakdown: any = {};
    
    Object.entries(categories).forEach(([category, types]) => {
      breakdown[category] = {
        count: 0,
        issues: []
      };
      
      types.forEach(type => {
        if (vulnerabilities[type] && Array.isArray(vulnerabilities[type]) && vulnerabilities[type].length > 0) {
          breakdown[category].count += vulnerabilities[type].length;
          breakdown[category].issues.push({
            type,
            name: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
            count: vulnerabilities[type].length
          });
        } else if (vulnerabilities[type] && typeof vulnerabilities[type] === 'string') {
          // Handle string-based findings like security headers
          if (type === 'security_headers' && vulnerabilities[type].includes('MISSING_SECURITY_HEADERS:')) {
            const headersStr = vulnerabilities[type].replace('MISSING_SECURITY_HEADERS: ', '');
            const headers = headersStr.split(',').filter((h: string) => h.trim()).map((h: string) => h.trim());
            breakdown[category].count += headers.length;
            breakdown[category].issues.push({
              type,
              name: 'Missing Security Headers',
              count: headers.length,
              details: headers
            });
          } else {
            breakdown[category].count += 1;
            breakdown[category].issues.push({
              type,
              name: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
              count: 1
            });
          }
        }
      });
    });
    
    return breakdown;
  };

  const metrics = getSecurityMetrics();
  const vulnerabilityBreakdown = getVulnerabilityBreakdown();

  // Function to fetch AI recommendations
  const fetchAiRecommendations = async () => {
    if (aiRecommendations.loading || aiRecommendations.priority1) return; // Don't fetch if already loading or loaded
    
    setAiRecommendations(prev => ({ ...prev, loading: true }));
    
    try {
      const response = await scanAPI.generateRecommendations(metrics);
      setAiRecommendations({
        loading: false,
        priority1: response.data.priority1,
        priority2: response.data.priority2
      });
    } catch (error: any) {
      console.error('Failed to generate AI recommendations:', error);
      setAiRecommendations({
        loading: false,
        priority1: 'Fix critical vulnerabilities within 24-48 hours. Implement proper input validation and secure authentication mechanisms.',
        priority2: 'Deploy WAF protection, implement automated security testing, and establish continuous monitoring workflows.',
        error: 'AI recommendations unavailable - using fallback'
      });
    }
  };

  // Fetch AI recommendations when metrics are available
  useEffect(() => {
    if (report && metrics.total > 0) {
      fetchAiRecommendations();
    }
  }, [report, metrics.total]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  // Function to categorize vulnerability type by severity
  const categorizeVulnerabilityTypeBySeverity = (type: string): 'critical' | 'high' | 'medium' | 'low' => {
    // Critical vulnerabilities (CVSS >= 8.5)
    const criticalTypes = ['sql_injection', 'command_injection', 'xxe', 'ssrf', 'double_spending', 'race_conditions', 'https', 'open_endpoint'];
    // High vulnerabilities (CVSS 7.0-8.4)
    const highTypes = ['xss', 'nosql_injection', 'ldap_injection', 'path_traversal', 'auth_bypass', 'privilege_escalation', 'bola_attacks', 'transaction_manipulation', 'session_fixation', 'kyc_bypass', 'loan_abuse', 'webhook_abuse', 'open_redirects'];
    // Medium vulnerabilities (CVSS 4.0-6.9)
    const mediumTypes = ['security_headers', 'security_header', 'cors', 'rate_limiting', 'error_handling', 'metadata_leakage', 'verbose_errors', 'discount_abuse', 'micro_transactions', 'idempotency_check'];
    // Low vulnerabilities (CVSS < 4.0)
    const lowTypes = ['general', 'information_disclosure'];
    
    if (criticalTypes.includes(type)) return 'critical';
    if (highTypes.includes(type)) return 'high';
    if (mediumTypes.includes(type)) return 'medium';
    return 'low';
  };

  // Function to show vulnerability details
  const showVulnerabilityDetails = (severity: 'critical' | 'high' | 'medium' | 'low', issues: { name: string; details?: any }[]) => {
    setVulnerabilityDrawer({
      open: true,
      severity,
      issues
    });
  };

  if (loading) {
    return (
      <Container maxWidth="lg">
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minHeight: 400, justifyContent: 'center' }}>
          <CircularProgress size={60} sx={{ mb: 2 }} />
          <Typography variant="h6" color="text.secondary">
            Loading Security Report...
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Analyzing {scanId?.slice(0, 8)}...
          </Typography>
        </Box>
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg">
        <Alert severity="error" sx={{ mt: 4 }}>
          <Typography variant="h6" gutterBottom>Report Loading Failed</Typography>
          <Typography variant="body2">{error}</Typography>
        </Alert>
        <Box sx={{ mt: 2 }}>
          <Button startIcon={<BackIcon />} onClick={handleBack} variant="contained">
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
          <Typography variant="h6" gutterBottom>Report Not Found</Typography>
          <Typography variant="body2">The requested security report could not be found.</Typography>
        </Alert>
        <Box sx={{ mt: 2 }}>
          <Button startIcon={<BackIcon />} onClick={handleBack} variant="contained">
            Back to History
          </Button>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      {/* Breadcrumb Navigation */}
      <Breadcrumbs aria-label="breadcrumb" sx={{ mb: 3 }}>
        <Link
          underline="hover"
          color="inherit"
          onClick={() => navigate('/')}
          sx={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <SecurityIcon fontSize="small" />
          Dashboard
        </Link>
        <Link
          underline="hover"
          color="inherit"
          onClick={() => navigate('/wiki')}
          sx={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <WikiIcon fontSize="small" />
          Security Wiki
        </Link>
        <Link
          underline="hover"
          color="inherit"
          onClick={() => navigate('/history')}
          sx={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <AssessmentIcon fontSize="small" />
          Scan History
        </Link>
        <Typography color="text.primary" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <BugIcon fontSize="small" />
          Report {scanId?.slice(0, 8)}
        </Typography>
      </Breadcrumbs>

      {/* Enhanced Header Section with Security Score Dashboard */}
      <Paper elevation={3} sx={{ p: isMobile ? 3 : 4, mb: 4, borderRadius: 3, background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)', color: 'white' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3, flexDirection: isMobile ? 'column' : 'row', gap: 2 }}>
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant={isMobile ? "h4" : "h3"} component="h1" gutterBottom sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 2 }}>
              🛡️ Security Assessment Report
              <Chip
                label={metrics.riskLevel}
                color={metrics.riskColor as any}
                sx={{ fontSize: '0.8rem', fontWeight: 'bold' }}
              />
            </Typography>
            <Typography variant="h6" sx={{ opacity: 0.9, mb: 2 }}>
              Comprehensive security analysis and vulnerability assessment
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
              <Chip 
                label={`Scan ID: ${scanId?.slice(0, 8)}...`} 
                variant="outlined" 
                size="medium"
                icon={<SecurityIcon />}
                sx={{ color: 'white', borderColor: 'white' }}
              />
              <Chip 
                label={`Duration: ${formatDuration(report.duration)}`} 
                variant="outlined" 
                size="medium"
                icon={<TimeIcon />}
                sx={{ color: 'white', borderColor: 'white' }}
              />
              <Chip 
                label={`Completed: ${new Date(report.end_time).toLocaleDateString()}`} 
                variant="outlined" 
                size="medium"
                icon={<CheckIcon />}
                sx={{ color: 'white', borderColor: 'white' }}
              />
            </Box>
          </Box>
          
          <Box sx={{ display: 'flex', gap: 1, flexDirection: isMobile ? 'row' : 'column' }}>
            <Tooltip title="Download Report">
              <IconButton
                onClick={handleDownload}
                sx={{ 
                  backgroundColor: 'rgba(255,255,255,0.2)',
                  color: 'white',
                  '&:hover': { backgroundColor: 'rgba(255,255,255,0.3)' }
                }}
              >
                <DownloadIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Share Report">
              <IconButton
                onClick={handleShare}
                sx={{ 
                  backgroundColor: 'rgba(255,255,255,0.2)',
                  color: 'white',
                  '&:hover': { backgroundColor: 'rgba(255,255,255,0.3)' }
                }}
              >
                <ShareIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Print Report">
              <IconButton
                onClick={handlePrint}
                sx={{ 
                  backgroundColor: 'rgba(255,255,255,0.2)',
                  color: 'white',
                  '&:hover': { backgroundColor: 'rgba(255,255,255,0.3)' }
                }}
              >
                <PrintIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Security Score Dashboard */}
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <Box sx={{ position: 'relative', display: 'inline-flex', mb: 2 }}>
                  <CircularProgress
                    variant="determinate"
                    value={metrics.score}
                    size={80}
                    thickness={4}
                    sx={{ color: 'white' }}
                  />
                  <Box
                    sx={{
                      top: 0,
                      left: 0,
                      bottom: 0,
                      right: 0,
                      position: 'absolute',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Typography variant="h6" component="div" color="white" fontWeight="bold">
                      {metrics.score}
                    </Typography>
                  </Box>
                </Box>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Security Score
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <ErrorIcon sx={{ fontSize: 40, mb: 1, opacity: 0.9 }} />
                <Tooltip title="Click chips below to view detailed breakdown" arrow>
                  <Typography 
                    variant={isMobile ? "h5" : "h4"} 
                    sx={{ 
                      fontWeight: 'bold',
                      cursor: 'help'
                    }}
                  >
                    {metrics.total}
                  </Typography>
                </Tooltip>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Total Issues Found
                </Typography>
                                  <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1, mt: 1, flexWrap: 'wrap' }}>
                    <Chip 
                      label={`${metrics.critical}🔴`} 
                      size="small" 
                      sx={{ 
                        color: 'white', 
                        border: '1px solid white',
                        cursor: 'pointer',
                        '&:hover': {
                          backgroundColor: 'rgba(255,255,255,0.2)',
                          transform: 'scale(1.05)'
                        },
                        transition: 'all 0.2s ease'
                      }} 
                      variant="outlined" 
                      onClick={() => showVulnerabilityDetails('critical', metrics.issues.critical)} 
                    />
                    <Chip 
                      label={`${metrics.high}🟠`} 
                      size="small" 
                      sx={{ 
                        color: 'white', 
                        border: '1px solid white',
                        cursor: 'pointer',
                        '&:hover': {
                          backgroundColor: 'rgba(255,255,255,0.2)',
                          transform: 'scale(1.05)'
                        },
                        transition: 'all 0.2s ease'
                      }} 
                      variant="outlined" 
                      onClick={() => showVulnerabilityDetails('high', metrics.issues.high)} 
                    />
                    <Chip 
                      label={`${metrics.medium}🟡`} 
                      size="small" 
                      sx={{ 
                        color: 'white', 
                        border: '1px solid white',
                        cursor: 'pointer',
                        '&:hover': {
                          backgroundColor: 'rgba(255,255,255,0.2)',
                          transform: 'scale(1.05)'
                        },
                        transition: 'all 0.2s ease'
                      }} 
                      variant="outlined" 
                      onClick={() => showVulnerabilityDetails('medium', metrics.issues.medium)} 
                    />
                  </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <SpeedIcon sx={{ fontSize: isMobile ? 40 : 50, mb: 1, opacity: 0.9 }} />
                <Typography variant={isMobile ? "h5" : "h4"} sx={{ fontWeight: 'bold' }}>
                  {formatDuration(report.duration)}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Scan Duration
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                  <CheckIcon sx={{ fontSize: 40, opacity: 0.9 }} />
                  <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                    Complete
                  </Typography>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>
                    Scan Status
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {/* Navigation and Action Buttons */}
      <Paper elevation={2} sx={{ p: 2, mb: 3, borderRadius: 2 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              startIcon={<BackIcon />}
              onClick={handleBack}
              variant="outlined"
            >
              Back to History
            </Button>
            <Button
              startIcon={<WikiIcon />}
              onClick={handleWiki}
              variant="outlined"
              color="info"
            >
              Security Wiki
            </Button>
          </Box>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              onClick={handleDownload}
            >
              Download Report
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Vulnerability Breakdown by Category - Now positioned right after header */}
      {Object.keys(vulnerabilityBreakdown).length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 4, borderRadius: 2 }}>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
            <CategoryIcon color="primary" />
            Vulnerability Analysis by Category
          </Typography>
          <Grid container spacing={3}>
            {Object.entries(vulnerabilityBreakdown).map(([category, data]: [string, any]) => {
              if (data.count === 0) return null;
              
              // Dynamic category icons based on category names from data
              const getCategoryIcon = (categoryName: string) => {
                if (categoryName.includes('Injection')) return <BugIcon />;
                if (categoryName.includes('Banking')) return <BankIcon />;
                if (categoryName.includes('Authentication') || categoryName.includes('Authorization')) return <VpnIcon />;
                if (categoryName.includes('Information') || categoryName.includes('Disclosure')) return <InfoIcon />;
                if (categoryName.includes('Configuration') || categoryName.includes('Security')) return <SettingsIcon />;
                if (categoryName.includes('Path') || categoryName.includes('Redirect')) return <WebIcon />;
                if (categoryName.includes('Service') || categoryName.includes('External')) return <DataIcon />;
                return <WarningIcon />; // Default icon
              };
              
              const getCategoryColor = (count: number) => {
                if (count >= 5) return 'error';
                if (count >= 3) return 'warning';
                if (count >= 1) return 'info';
                return 'success';
              };
              
              return (
                <Grid item xs={12} sm={6} md={4} key={category}>
                  <Card 
                    variant="outlined" 
                    sx={{ 
                      p: 2, 
                      height: '100%',
                      border: `2px solid`,
                      borderColor: `${getCategoryColor(data.count)}.main`,
                      '&:hover': {
                        transform: 'translateY(-2px)',
                        boxShadow: 3
                      },
                      transition: 'all 0.2s ease-in-out'
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      {getCategoryIcon(category)}
                      <Typography variant="h6" sx={{ fontWeight: 'bold' }}>{category}</Typography>
                    </Box>
                    <Box 
                      sx={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: 2, 
                        mb: 2,
                        cursor: 'pointer',
                        '&:hover': {
                          opacity: 0.8
                        }
                      }}
                      onClick={() => {
                        // Collect all issues from this category with their severity
                        const categoryIssues: { name: string; details?: any }[] = [];
                        let primarySeverity: 'critical' | 'high' | 'medium' | 'low' = 'low';
                        
                        data.issues.forEach((issue: any) => {
                          // Determine severity based on vulnerability type
                          const severity = categorizeVulnerabilityTypeBySeverity(issue.type);
                          if (severity === 'critical' && primarySeverity !== 'critical') primarySeverity = 'critical';
                          else if (severity === 'high' && primarySeverity !== 'critical' && primarySeverity !== 'high') primarySeverity = 'high';
                          else if (severity === 'medium' && primarySeverity !== 'critical' && primarySeverity !== 'high' && primarySeverity !== 'medium') primarySeverity = 'medium';
                          
                          categoryIssues.push({
                            name: issue.name,
                            details: issue.details || `${issue.count} instance${issue.count > 1 ? 's' : ''} found`
                          });
                        });
                        
                        showVulnerabilityDetails(primarySeverity, categoryIssues);
                      }}
                    >
                      <Typography variant="h3" color={getCategoryColor(data.count)} sx={{ fontWeight: 'bold' }}>
                        {data.count}
                      </Typography>
                      <Box>
                        <Typography variant="body1" color="text.secondary">
                          issue{data.count !== 1 ? 's' : ''} found
                        </Typography>
                        <Typography variant="caption" color="primary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          Click to view details <ArrowRightIcon fontSize="small" />
                        </Typography>
                      </Box>
                    </Box>
                    <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
                      {data.issues.map((issue: any, index: number) => (
                        <ListItem key={index} sx={{ px: 0, py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 30 }}>
                            <WarningIcon color="warning" fontSize="small" />
                          </ListItemIcon>
                          <ListItemText 
                            primary={
                              <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                {issue.name}
                              </Typography>
                            }
                            secondary={
                              <Typography variant="caption" color="text.secondary">
                                {issue.details ? 
                                  `${issue.count} instance${issue.count > 1 ? 's' : ''}: ${Array.isArray(issue.details) ? issue.details.join(', ') : issue.details}` :
                                  `${issue.count} instance${issue.count > 1 ? 's' : ''}`
                                }
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        </Paper>
      )}

      {/* AI-Powered Security Recommendations - Highlight Section */}
      <Paper elevation={3} sx={{ p: 4, mb: 4, borderRadius: 3, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
        <Typography variant="h4" gutterBottom sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          🤖 AI Security Recommendations
          {aiRecommendations.loading && <CircularProgress size={24} sx={{ color: 'white' }} />}
        </Typography>
        
        {aiRecommendations.loading ? (
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', p: 4 }}>
            <CircularProgress size={40} sx={{ mr: 2, color: 'white' }} />
            <Typography variant="h6" sx={{ opacity: 0.9 }}>
              AI analyzing your security findings...
            </Typography>
          </Box>
        ) : (
          <Grid container spacing={3}>
            {metrics.critical > 0 && (
              <Grid item xs={12}>
                <Card sx={{ p: 3, bgcolor: 'rgba(255,255,255,0.95)', border: '3px solid #d32f2f' }}>
                  <Typography variant="h5" gutterBottom sx={{ color: '#d32f2f', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
                    🚨 CRITICAL PRIORITY
                  </Typography>
                                     <Typography variant="h6" sx={{ lineHeight: 1.6, color: '#d32f2f', fontWeight: 500, whiteSpace: 'pre-line' }}>
                     {aiRecommendations.priority1}
                   </Typography>
                </Card>
              </Grid>
            )}
            
            {metrics.high > 0 && (
              <Grid item xs={12}>
                <Card sx={{ p: 3, bgcolor: 'rgba(255,255,255,0.95)', border: '3px solid #f57c00' }}>
                  <Typography variant="h5" gutterBottom sx={{ color: '#f57c00', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
                    ⚠️ HIGH PRIORITY
                  </Typography>
                                     <Typography variant="h6" sx={{ lineHeight: 1.6, color: '#f57c00', fontWeight: 500, whiteSpace: 'pre-line' }}>
                     {metrics.high >= metrics.critical ? aiRecommendations.priority1 : aiRecommendations.priority2}
                   </Typography>
                </Card>
              </Grid>
            )}
            
            {metrics.medium > 0 && !metrics.critical && !metrics.high && (
              <Grid item xs={12}>
                <Card sx={{ p: 3, bgcolor: 'rgba(255,255,255,0.95)', border: '3px solid #1976d2' }}>
                  <Typography variant="h5" gutterBottom sx={{ color: '#1976d2', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
                    📋 MEDIUM PRIORITY
                  </Typography>
                                     <Typography variant="h6" sx={{ lineHeight: 1.6, color: '#1976d2', fontWeight: 500, whiteSpace: 'pre-line' }}>
                     {aiRecommendations.priority2}
                   </Typography>
                </Card>
              </Grid>
            )}
            
            {metrics.total === 0 && (
              <Grid item xs={12}>
                <Card sx={{ p: 3, bgcolor: 'rgba(255,255,255,0.95)', border: '3px solid #4caf50' }}>
                  <Typography variant="h5" gutterBottom sx={{ color: '#4caf50', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
                    ✅ EXCELLENT SECURITY
                  </Typography>
                                     <Typography variant="h6" sx={{ lineHeight: 1.6, color: '#4caf50', fontWeight: 500, whiteSpace: 'pre-line' }}>
                     • Implement automated SAST/DAST scanning in CI/CD pipeline{'\n'}• Deploy security monitoring with SIEM integration{'\n'}• Add API rate limiting and request throttling
                   </Typography>
                </Card>
              </Grid>
            )}
          </Grid>
        )}
        
        <Box sx={{ mt: 3, p: 2, bgcolor: 'rgba(255,255,255,0.1)', borderRadius: 1, border: '1px solid rgba(255,255,255,0.2)' }}>
          <Typography variant="body2" sx={{ opacity: 0.9, display: 'flex', alignItems: 'center', gap: 1 }}>
            🎯 Personalized recommendations based on fintech security best practices
          </Typography>
        </Box>
      </Paper>

      {/* Tabbed Information Sections */}
      <Paper elevation={2} sx={{ borderRadius: 2, mb: 4 }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs 
            value={tabValue} 
            onChange={handleTabChange} 
            aria-label="report sections"
            variant={isMobile ? "scrollable" : "standard"}
            scrollButtons="auto"
          >
            <Tab 
              label="Scan Metadata" 
              icon={<InfoIcon />} 
              iconPosition="start"
              sx={{ minHeight: 64 }}
            />
            <Tab 
              label="Detailed Report" 
              icon={<AssessmentIcon />} 
              iconPosition="start"
              sx={{ minHeight: 64 }}
            />
            <Tab 
              label="Technical Details" 
              icon={<CodeIcon />} 
              iconPosition="start"
              sx={{ minHeight: 64 }}
            />
            <Tab 
              label="WAF Blocked Requests" 
              icon={<ShieldIcon />} 
              iconPosition="start"
              sx={{ minHeight: 64 }}
            />
          </Tabs>
        </Box>

        {/* Scan Metadata Tab */}
        <CustomTabPanel value={tabValue} index={0}>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <InfoIcon color="primary" />
            Scan Execution Details
          </Typography>
          
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell><strong>Attribute</strong></TableCell>
                  <TableCell><strong>Value</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <SecurityIcon fontSize="small" />
                      Scan ID
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', p: 1, borderRadius: 1 }}>
                      {scanId}
                    </Typography>
                  </TableCell>
                  <TableCell>Unique identifier for this security scan</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <WebIcon fontSize="small" />
                      Target URL
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography 
                      variant="body2" 
                      sx={{ 
                        fontFamily: 'monospace', 
                        bgcolor: 'grey.100', 
                        p: 1, 
                        borderRadius: 1,
                        wordBreak: 'break-all',
                        maxWidth: '400px'
                      }}
                    >
                      {report.target_url || 'N/A'}
                    </Typography>
                  </TableCell>
                  <TableCell>The API endpoint or URL that was scanned for vulnerabilities</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <TimeIcon fontSize="small" />
                      Duration
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip label={formatDuration(report.duration)} color="info" />
                  </TableCell>
                  <TableCell>Total time taken to complete the security scan</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <RunIcon fontSize="small" />
                      Start Time
                    </Box>
                  </TableCell>
                  <TableCell>{new Date(report.start_time).toLocaleString()}</TableCell>
                  <TableCell>When the security scan was initiated</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <CheckIcon fontSize="small" />
                      End Time
                    </Box>
                  </TableCell>
                  <TableCell>{new Date(report.end_time).toLocaleString()}</TableCell>
                  <TableCell>When the security scan was completed</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <AssessmentIcon fontSize="small" />
                      Security Score
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <CircularProgress
                        variant="determinate"
                        value={metrics.score}
                        size={30}
                        thickness={4}
                      />
                      <Typography variant="h6">{metrics.score}/100</Typography>
                      <Chip label={metrics.riskLevel} color={metrics.riskColor as any} size="small" />
                    </Box>
                  </TableCell>
                  <TableCell>Overall security assessment score based on vulnerabilities found</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <WarningIcon fontSize="small" />
                      Total Issues
                    </Box>
                  </TableCell>
                                      <TableCell>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        <Chip 
                          label={`${metrics.critical} Critical`} 
                          color="error" 
                          size="small" 
                          onClick={() => showVulnerabilityDetails('critical', metrics.issues.critical)}
                          sx={{ cursor: 'pointer', '&:hover': { transform: 'scale(1.05)' } }}
                        />
                        <Chip 
                          label={`${metrics.high} High`} 
                          color="warning" 
                          size="small" 
                          onClick={() => showVulnerabilityDetails('high', metrics.issues.high)}
                          sx={{ cursor: 'pointer', '&:hover': { transform: 'scale(1.05)' } }}
                        />
                        <Chip 
                          label={`${metrics.medium} Medium`} 
                          color="info" 
                          size="small" 
                          onClick={() => showVulnerabilityDetails('medium', metrics.issues.medium)}
                          sx={{ cursor: 'pointer', '&:hover': { transform: 'scale(1.05)' } }}
                        />
                        <Chip 
                          label={`${metrics.low} Low`} 
                          color="success" 
                          size="small" 
                          onClick={() => showVulnerabilityDetails('low', metrics.issues.low)}
                          sx={{ cursor: 'pointer', '&:hover': { transform: 'scale(1.05)' } }}
                        />
                      </Box>
                    </TableCell>
                  <TableCell>Breakdown of security issues by severity level</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </CustomTabPanel>

        {/* Detailed Report Tab */}
        <CustomTabPanel value={tabValue} index={1}>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 4 }}>
            <AssessmentIcon color="primary" />
            Interactive Security Analysis Dashboard
          </Typography>

          {/* Executive Summary Section */}
          <Paper elevation={3} sx={{ p: 4, mb: 4, borderRadius: 3, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
              📊 Executive Summary
            </Typography>
            <Grid container spacing={3} sx={{ mt: 2 }}>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                  <Box sx={{ 
                    width: 60, 
                    height: 60, 
                    borderRadius: '50%', 
                    bgcolor: 'rgba(255,255,255,0.2)', 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'center',
                    fontSize: '24px'
                  }}>
                    {metrics.score >= 90 ? '🛡️' : metrics.score >= 70 ? '⚠️' : '🚨'}
                  </Box>
                  <Box>
                    <Typography variant="h4" sx={{ fontWeight: 'bold' }}>{metrics.score}/100</Typography>
                    <Typography variant="h6">{metrics.riskLevel}</Typography>
                  </Box>
                </Box>
                <Typography variant="body1" sx={{ opacity: 0.9, lineHeight: 1.6 }}>
                  {metrics.score >= 90 
                    ? "Excellent security posture with minimal vulnerabilities detected. Your API demonstrates strong security controls."
                    : metrics.score >= 70 
                    ? "Good security foundation but some areas need attention. Address medium and high severity issues promptly."
                    : "Critical security concerns identified. Immediate action required to secure your API endpoints."
                  }
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <Box sx={{ textAlign: 'center', minWidth: 100 }}>
                    <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#ff4444' }}>{metrics.critical}</Typography>
                    <Typography variant="caption">Critical</Typography>
                  </Box>
                  <Box sx={{ textAlign: 'center', minWidth: 100 }}>
                    <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#ff9800' }}>{metrics.high}</Typography>
                    <Typography variant="caption">High</Typography>
                  </Box>
                  <Box sx={{ textAlign: 'center', minWidth: 100 }}>
                    <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#2196f3' }}>{metrics.medium}</Typography>
                    <Typography variant="caption">Medium</Typography>
                  </Box>
                  <Box sx={{ textAlign: 'center', minWidth: 100 }}>
                    <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#4caf50' }}>{metrics.low}</Typography>
                    <Typography variant="caption">Low</Typography>
                  </Box>
                </Box>
                <Typography variant="body2" sx={{ mt: 2, opacity: 0.9 }}>
                  Total vulnerabilities found: <strong>{metrics.total}</strong>
                </Typography>
              </Grid>
            </Grid>
          </Paper>

          {/* Priority Actions Section */}
          {(metrics.critical > 0 || metrics.high > 0) && (
            <Paper elevation={2} sx={{ p: 3, mb: 4, borderRadius: 2, border: '2px solid', borderColor: 'error.main' }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'error.main' }}>
                🚨 Immediate Action Required
              </Typography>
              <Alert severity="error" sx={{ mb: 2 }}>
                <Typography variant="subtitle2" gutterBottom>Critical vulnerabilities detected!</Typography>
                <Typography variant="body2">
                  These issues pose significant security risks and should be addressed immediately to prevent potential data breaches or system compromise.
                </Typography>
              </Alert>
              <Grid container spacing={2}>
                {metrics.critical > 0 && (
                  <Grid item xs={12} sm={6}>
                    <Card sx={{ bgcolor: 'error.light', color: 'error.contrastText' }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>🔴 Critical Issues: {metrics.critical}</Typography>
                        <List dense>
                          {metrics.issues.critical.slice(0, 3).map((issue, index) => (
                            <ListItem key={index} sx={{ py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 30 }}>
                                <ErrorIcon color="inherit" fontSize="small" />
                              </ListItemIcon>
                              <ListItemText 
                                primary={issue.name}
                                primaryTypographyProps={{ variant: 'body2', fontWeight: 'medium' }}
                              />
                            </ListItem>
                          ))}
                        </List>
                        <Button 
                          size="small" 
                          variant="contained" 
                          sx={{ mt: 1, bgcolor: 'error.dark' }}
                          onClick={() => showVulnerabilityDetails('critical', metrics.issues.critical)}
                        >
                          View All Critical Issues
                        </Button>
                      </CardContent>
                    </Card>
                  </Grid>
                )}
                {metrics.high > 0 && (
                  <Grid item xs={12} sm={6}>
                    <Card sx={{ bgcolor: 'warning.light', color: 'warning.contrastText' }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>🟠 High Priority: {metrics.high}</Typography>
                        <List dense>
                          {metrics.issues.high.slice(0, 3).map((issue, index) => (
                            <ListItem key={index} sx={{ py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 30 }}>
                                <WarningIcon color="inherit" fontSize="small" />
                              </ListItemIcon>
                              <ListItemText 
                                primary={issue.name}
                                primaryTypographyProps={{ variant: 'body2', fontWeight: 'medium' }}
                              />
                            </ListItem>
                          ))}
                        </List>
                        <Button 
                          size="small" 
                          variant="contained" 
                          sx={{ mt: 1, bgcolor: 'warning.dark' }}
                          onClick={() => showVulnerabilityDetails('high', metrics.issues.high)}
                        >
                          View All High Issues
                        </Button>
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </Grid>
            </Paper>
          )}

          {/* Security Posture Overview */}
          <Paper elevation={2} sx={{ p: 3, mb: 4, borderRadius: 2 }}>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              🛡️ Security Posture Analysis
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                    🔍 Attack Surface Analysis
                  </Typography>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="body2">Endpoints Scanned:</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                      {report.findings?.api ? Object.keys(report.findings.api).length : 'N/A'}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="body2">Security Headers:</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 'bold', color: metrics.issues.medium.some(i => i.name.includes('Security Header')) ? 'error.main' : 'success.main' }}>
                      {metrics.issues.medium.some(i => i.name.includes('Security Header')) ? 'Missing' : 'Configured'}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="body2">Authentication:</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 'bold', color: metrics.issues.high.some(i => i.name.includes('auth') || i.name.includes('Auth')) ? 'error.main' : 'success.main' }}>
                      {metrics.issues.high.some(i => i.name.includes('auth') || i.name.includes('Auth')) ? 'Vulnerable' : 'Protected'}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                    <Typography variant="body2">Injection Protection:</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 'bold', color: metrics.issues.critical.some(i => i.name.includes('injection') || i.name.includes('Injection')) ? 'error.main' : 'success.main' }}>
                      {metrics.issues.critical.some(i => i.name.includes('injection') || i.name.includes('Injection')) ? 'Vulnerable' : 'Protected'}
                    </Typography>
                  </Box>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                    📈 Security Trends & Recommendations
                  </Typography>
                  {metrics.score >= 90 ? (
                    <Alert severity="success" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        🎉 Excellent security posture! Continue monitoring and maintain current practices.
                      </Typography>
                    </Alert>
                  ) : metrics.score >= 70 ? (
                    <Alert severity="warning" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        ⚠️ Good foundation. Focus on addressing medium and high priority issues.
                      </Typography>
                    </Alert>
                  ) : (
                    <Alert severity="error" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        🚨 Critical action needed. Prioritize fixing high and critical vulnerabilities.
                      </Typography>
                    </Alert>
                  )}
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Next Steps:</strong>
                  </Typography>
                  <List dense>
                    {metrics.critical > 0 && (
                      <ListItem sx={{ py: 0.2 }}>
                        <ListItemIcon sx={{ minWidth: 20 }}>
                          <Typography variant="body2">1.</Typography>
                        </ListItemIcon>
                        <ListItemText 
                          primary="Address critical vulnerabilities immediately"
                          primaryTypographyProps={{ variant: 'body2' }}
                        />
                      </ListItem>
                    )}
                    {metrics.high > 0 && (
                      <ListItem sx={{ py: 0.2 }}>
                        <ListItemIcon sx={{ minWidth: 20 }}>
                          <Typography variant="body2">{metrics.critical > 0 ? '2.' : '1.'}</Typography>
                        </ListItemIcon>
                        <ListItemText 
                          primary="Plan fixes for high priority issues"
                          primaryTypographyProps={{ variant: 'body2' }}
                        />
                      </ListItem>
                    )}
                    <ListItem sx={{ py: 0.2 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <Typography variant="body2">{(metrics.critical > 0 ? 1 : 0) + (metrics.high > 0 ? 1 : 0) + 1}.</Typography>
                      </ListItemIcon>
                      <ListItemText 
                        primary="Implement continuous security monitoring"
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  </List>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          {/* Detailed Vulnerability Breakdown */}
          <Paper elevation={2} sx={{ p: 3, mb: 4, borderRadius: 2 }}>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              🔬 Detailed Vulnerability Analysis
            </Typography>
            <Grid container spacing={2}>
              {(['critical', 'high', 'medium', 'low'] as const).map((severity) => {
                const severityData = metrics.issues[severity];
                if (severityData.length === 0) return null;
                
                const getSeverityColor = (sev: string) => {
                  switch (sev) {
                    case 'critical': return '#d32f2f';
                    case 'high': return '#f57c00';
                    case 'medium': return '#1976d2';
                    case 'low': return '#388e3c';
                    default: return '#757575';
                  }
                };

                const getSeverityIcon = (sev: string) => {
                  switch (sev) {
                    case 'critical': return '🔴';
                    case 'high': return '🟠';
                    case 'medium': return '🟡';
                    case 'low': return '🟢';
                    default: return '⚪';
                  }
                };

                return (
                  <Grid item xs={12} sm={6} md={3} key={severity}>
                    <Card 
                      sx={{ 
                        border: `2px solid ${getSeverityColor(severity)}`,
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                        '&:hover': {
                          transform: 'translateY(-4px)',
                          boxShadow: `0 8px 25px ${getSeverityColor(severity)}20`
                        }
                      }}
                      onClick={() => showVulnerabilityDetails(severity, severityData)}
                    >
                      <CardContent sx={{ textAlign: 'center', p: 2 }}>
                        <Typography variant="h2" sx={{ fontSize: '2rem' }}>
                          {getSeverityIcon(severity)}
                        </Typography>
                        <Typography variant="h4" sx={{ fontWeight: 'bold', color: getSeverityColor(severity) }}>
                          {severityData.length}
                        </Typography>
                        <Typography variant="h6" sx={{ textTransform: 'capitalize', fontWeight: 'bold' }}>
                          {severity}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Click to view details
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                );
              })}
            </Grid>
          </Paper>



          {/* Compliance & Standards */}
          <Paper elevation={2} sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              📋 Security Standards & Compliance
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={4}>
                <Card variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="h6" color="primary">OWASP API Top 10</Typography>
                  <Typography variant="h4" sx={{ fontWeight: 'bold', color: metrics.score >= 80 ? 'success.main' : 'error.main' }}>
                    {metrics.score >= 80 ? '✅' : '❌'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {metrics.score >= 80 ? 'Compliant' : 'Non-Compliant'}
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Card variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="h6" color="primary">Security Headers</Typography>
                  <Typography variant="h4" sx={{ fontWeight: 'bold', color: !metrics.issues.medium.some(i => i.name.includes('Security Header')) ? 'success.main' : 'error.main' }}>
                    {!metrics.issues.medium.some(i => i.name.includes('Security Header')) ? '✅' : '❌'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {!metrics.issues.medium.some(i => i.name.includes('Security Header')) ? 'Implemented' : 'Missing'}
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Card variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="h6" color="primary">Risk Level</Typography>
                  <Typography variant="h4" sx={{ fontWeight: 'bold', color: metrics.riskColor === 'success' ? 'success.main' : metrics.riskColor === 'warning' ? 'warning.main' : 'error.main' }}>
                    {metrics.riskLevel === 'EXCELLENT' ? '🟢' : metrics.riskLevel === 'GOOD' ? '🟡' : '🔴'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {metrics.riskLevel}
                  </Typography>
                </Card>
              </Grid>
            </Grid>
          </Paper>
        </CustomTabPanel>

        {/* Technical Details Tab */}
        <CustomTabPanel value={tabValue} index={2}>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CodeIcon color="primary" />
            Technical Scan Implementation Details
          </Typography>
          
          <Accordion expanded={expandedSection === 'findings'} onChange={() => setExpandedSection(expandedSection === 'findings' ? false : 'findings')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Raw Findings Data</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <SyntaxHighlighter
                language="json"
                style={atomOneDark}
                customStyle={{ borderRadius: '8px', fontSize: '12px' }}
              >
                {JSON.stringify(report.findings, null, 2)}
              </SyntaxHighlighter>
            </AccordionDetails>
          </Accordion>

          <Accordion expanded={expandedSection === 'metadata'} onChange={() => setExpandedSection(expandedSection === 'metadata' ? false : 'metadata')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Complete Scan Metadata</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell><strong>Scan ID</strong></TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{scanId}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell><strong>Duration (seconds)</strong></TableCell>
                      <TableCell>{report.duration}s</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell><strong>Start Time (UTC)</strong></TableCell>
                      <TableCell>{new Date(report.start_time).toISOString()}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell><strong>End Time (UTC)</strong></TableCell>
                      <TableCell>{new Date(report.end_time).toISOString()}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell><strong>Report Content Length</strong></TableCell>
                      <TableCell>{report.report_content.length} characters</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Accordion expanded={expandedSection === 'calculation'} onChange={() => setExpandedSection(expandedSection === 'calculation' ? false : 'calculation')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Security Score Calculation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Alert severity="info" sx={{ mb: 2 }}>
                Security score is calculated as: 100 - (Critical×40 + High×20 + Medium×10 + Low×5)
              </Alert>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>Severity</strong></TableCell>
                      <TableCell align="center"><strong>Count</strong></TableCell>
                      <TableCell align="center"><strong>Weight</strong></TableCell>
                      <TableCell align="center"><strong>Impact</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>Critical</TableCell>
                      <TableCell align="center">{metrics.critical}</TableCell>
                      <TableCell align="center">×40</TableCell>
                      <TableCell align="center">-{metrics.critical * 40}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>High</TableCell>
                      <TableCell align="center">{metrics.high}</TableCell>
                      <TableCell align="center">×20</TableCell>
                      <TableCell align="center">-{metrics.high * 20}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Medium</TableCell>
                      <TableCell align="center">{metrics.medium}</TableCell>
                      <TableCell align="center">×10</TableCell>
                      <TableCell align="center">-{metrics.medium * 10}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Low</TableCell>
                      <TableCell align="center">{metrics.low}</TableCell>
                      <TableCell align="center">×5</TableCell>
                      <TableCell align="center">-{metrics.low * 5}</TableCell>
                    </TableRow>
                    <TableRow sx={{ bgcolor: 'primary.light' }}>
                      <TableCell><strong>Final Score</strong></TableCell>
                      <TableCell align="center" colSpan={2}><strong>100 - {(metrics.critical * 40 + metrics.high * 20 + metrics.medium * 10 + metrics.low * 5)}</strong></TableCell>
                      <TableCell align="center"><strong>{metrics.score}</strong></TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        </CustomTabPanel>

        {/* WAF Blocked Requests Tab */}
        <CustomTabPanel value={tabValue} index={3}>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 4 }}>
            <ShieldIcon color="primary" />
            WAF Blocked Requests Analysis
          </Typography>

          {(() => {
            const securityLayers = report?.findings?.api?.security_layers;
            const blockedRequests: BlockedRequest[] = securityLayers?.blocked_requests || [];
            const wafBlocked = blockedRequests.filter((req: BlockedRequest) => req.layer_type === 'waf');
            
            if (!securityLayers?.waf_detected) {
              return (
                <Alert severity="info" sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>No WAF Protection Detected</Typography>
                  <Typography>
                    No Web Application Firewall (WAF) was detected during the security scan. 
                    Consider implementing WAF protection to block malicious requests before they reach your application.
                  </Typography>
                </Alert>
              );
            }

            if (wafBlocked.length === 0) {
              return (
                <Alert severity="warning" sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>WAF Detected but No Blocks Recorded</Typography>
                  <Typography>
                    A WAF was detected but no blocked requests were recorded during this scan. 
                    This could mean the WAF is configured very permissively or the scan didn't trigger any blocking rules.
                  </Typography>
                </Alert>
              );
            }

            // Group blocked requests by attack type
            const groupedBlocks = wafBlocked.reduce((acc: Record<string, BlockedRequest[]>, block: BlockedRequest) => {
              const attackType = block.attack_type || 'unknown';
              if (!acc[attackType]) {
                acc[attackType] = [];
              }
              acc[attackType].push(block);
              return acc;
            }, {} as Record<string, BlockedRequest[]>);

            return (
              <>
                {/* Summary Card */}
                <Paper elevation={3} sx={{ p: 3, mb: 4, borderRadius: 2, background: 'linear-gradient(135deg, #4CAF50 0%, #45a049 100%)', color: 'white' }}>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    🛡️ WAF Protection Summary
                  </Typography>
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={4}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h3" sx={{ fontWeight: 'bold' }}>{wafBlocked.length}</Typography>
                        <Typography variant="subtitle1">Total Blocked</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h3" sx={{ fontWeight: 'bold' }}>{Object.keys(groupedBlocks).length}</Typography>
                        <Typography variant="subtitle1">Attack Types</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                          {Math.round((wafBlocked[0]?.confidence || 0) * 100)}%
                        </Typography>
                        <Typography variant="subtitle1">Confidence</Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>

                {/* Blocked Requests by Attack Type */}
                {Object.entries(groupedBlocks).map(([attackType, blocks]: [string, BlockedRequest[]]) => (
                  <Accordion key={attackType} defaultExpanded sx={{ mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                        <Typography variant="h6" sx={{ textTransform: 'capitalize' }}>
                          {attackType.replace('_', ' ')} Attacks ({blocks.length} blocked)
                        </Typography>
                        <Chip 
                          label={`${blocks.length} blocked`} 
                          color="success" 
                          size="small" 
                        />
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <TableContainer component={Paper} variant="outlined">
                        <Table>
                          <TableHead>
                            <TableRow>
                              <TableCell><strong>Payload</strong></TableCell>
                              <TableCell><strong>Block Reason</strong></TableCell>
                              <TableCell align="center"><strong>Confidence</strong></TableCell>
                              <TableCell align="center"><strong>Layer Type</strong></TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {blocks.map((block: BlockedRequest, index: number) => (
                              <TableRow key={index} hover>
                                <TableCell>
                                  <Box sx={{ 
                                    fontFamily: 'monospace', 
                                    backgroundColor: '#f5f5f5', 
                                    padding: '8px', 
                                    borderRadius: '4px',
                                    border: '1px solid #ddd',
                                    wordBreak: 'break-all',
                                    maxWidth: '400px'
                                  }}>
                                    {block.payload}
                                  </Box>
                                </TableCell>
                                <TableCell>
                                  <Typography variant="body2" color="text.secondary">
                                    {block.block_reason}
                                  </Typography>
                                </TableCell>
                                <TableCell align="center">
                                  <Chip 
                                    label={`${Math.round(block.confidence * 100)}%`}
                                    color={block.confidence >= 0.8 ? 'success' : block.confidence >= 0.6 ? 'warning' : 'default'}
                                    size="small"
                                  />
                                </TableCell>
                                <TableCell align="center">
                                  <Chip 
                                    label={block.layer_type.toUpperCase()}
                                    color="primary"
                                    size="small"
                                  />
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </AccordionDetails>
                  </Accordion>
                ))}

                {/* Additional WAF Information */}
                <Paper elevation={1} sx={{ p: 3, mt: 3, borderRadius: 2 }}>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <InfoIcon color="primary" />
                    WAF Analysis Details
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>Detection Method:</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Connection failures and response patterns analysis
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>Security Benefit:</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Preventing {wafBlocked.length} potential attack attempts from reaching your application
                      </Typography>
                    </Grid>
                  </Grid>
                </Paper>
              </>
            );
          })()}
        </CustomTabPanel>
      </Paper>

      {/* Floating Action Button for quick actions */}
      <Fab
        color="primary"
        aria-label="actions"
        sx={{
          position: 'fixed',
          bottom: 16,
          right: 16,
          zIndex: 1000
        }}
        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
      >
        <SecurityIcon />
      </Fab>

      {/* Vulnerability Details Drawer */}
      <VulnerabilityDetailDrawer
        severity={vulnerabilityDrawer.severity}
        issues={vulnerabilityDrawer.issues}
        open={vulnerabilityDrawer.open}
        onClose={() => setVulnerabilityDrawer({ ...vulnerabilityDrawer, open: false })}
      />
    </Container>
  );
};

export default ReportDetail; 