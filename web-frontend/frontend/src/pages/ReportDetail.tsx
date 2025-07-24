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
  LinearProgress,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Breadcrumbs,
  Link,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  Download as DownloadIcon,
  GetApp as ExportIcon,
  Security as SecurityIcon,
  Schedule as TimeIcon,
  Assessment as AssessmentIcon,
  ExpandMore as ExpandMoreIcon,
  Shield as ShieldIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  BugReport as BugIcon,
  Code as CodeIcon,
  PlayArrow as RunIcon,
  MenuBook as WikiIcon,
  Share as ShareIcon,
  Print as PrintIcon,
  TrendingUp as TrendingUpIcon,
  Speed as SpeedIcon,
  AccountBalance as BankIcon,
  VpnLock as VpnIcon,
  DataObject as DataIcon,
  Web as WebIcon,
  Settings as SettingsIcon,
  NavigateNext as NextIcon,
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

interface SecurityMetrics {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  score: number;
  riskLevel: string;
  riskColor: string;
}

interface SecurityLayer {
  type: string;
  confidence: number;
  blockReason: string;
  partialProtection?: boolean;
  blockRate?: string;
}

interface SecurityLayerInfo {
  totalBlocked: number;
  layerTypes: string[];
  attackTypes: string[];
  wafDetected: boolean;
  rateLimitDetected: boolean;
  authBlocksDetected: boolean;
  captchaDetected: boolean;
  challengeDetected: boolean;
  securityLayers: SecurityLayer[];
}

const ReportDetail: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [expandedSection, setExpandedSection] = useState<string | false>('overview');

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

  // Calculate comprehensive security metrics
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
        riskColor: 'grey'
      };
    }
    
    const findings = report.findings.api;
    let critical = 0, high = 0, medium = 0, low = 0;
    
    // Handle new structure with vulnerabilities
    const vulnerabilities = findings.vulnerabilities || findings;
    
    // Handle severity-based structure
    if (vulnerabilities.critical && Array.isArray(vulnerabilities.critical)) {
      critical = vulnerabilities.critical.length;
    }
    if (vulnerabilities.high && Array.isArray(vulnerabilities.high)) {
      high = vulnerabilities.high.length;
    }
    if (vulnerabilities.medium && Array.isArray(vulnerabilities.medium)) {
      medium = vulnerabilities.medium.length;
    }
    if (vulnerabilities.low && Array.isArray(vulnerabilities.low)) {
      low = vulnerabilities.low.length;
    }
    
    // Handle legacy type-based structure
    const criticalTypes = ['sql_injection', 'command_injection', 'xxe', 'ssrf', 'double_spending', 'race_conditions'];
    const highTypes = ['xss', 'nosql_injection', 'ldap_injection', 'path_traversal', 'privilege_escalation', 'bola_attacks'];
    const mediumTypes = ['security_headers', 'metadata_leakage', 'verbose_errors', 'rate_limiting'];
    
    if (!vulnerabilities.critical) {
      criticalTypes.forEach(type => {
        if (vulnerabilities[type] && Array.isArray(vulnerabilities[type])) {
          critical += vulnerabilities[type].length;
        }
      });
    }
    
    if (!vulnerabilities.high) {
      highTypes.forEach(type => {
        if (vulnerabilities[type] && Array.isArray(vulnerabilities[type])) {
          high += vulnerabilities[type].length;
        }
      });
    }

    if (!vulnerabilities.medium) {
      mediumTypes.forEach(type => {
        if (vulnerabilities[type] && Array.isArray(vulnerabilities[type])) {
          medium += vulnerabilities[type].length;
        } else if (vulnerabilities[type] && typeof vulnerabilities[type] === 'string') {
          // Handle string-based findings like security headers
          if (type === 'security_headers' && vulnerabilities[type].includes('MISSING_SECURITY_HEADERS:')) {
            const headersStr = vulnerabilities[type].replace('MISSING_SECURITY_HEADERS: ', '');
            const headerCount = headersStr.split(',').filter((h: string) => h.trim()).length;
            medium += headerCount;
          } else {
            medium += 1; // Count other string findings as 1 issue
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
    
    return { critical, high, medium, low, total, score, riskLevel, riskColor };
  };

  // Get detailed security layer information
  const getSecurityLayerInfo = (): SecurityLayerInfo | null => {
    if (!report?.findings?.api?.security_layers) return null;
    
    const securityLayers = report.findings.api.security_layers;
    const blockedRequests = securityLayers.blocked_requests || [];
    
    return {
      totalBlocked: blockedRequests.length,
      layerTypes: Array.from(new Set(blockedRequests.map((block: any) => block.layer_type))),
      attackTypes: Array.from(new Set(blockedRequests.map((block: any) => block.attack_type || 'unknown'))),
      wafDetected: securityLayers.waf_detected || false,
      rateLimitDetected: securityLayers.rate_limiting_detected || false,
      authBlocksDetected: securityLayers.auth_blocks_detected || false,
      captchaDetected: securityLayers.captcha_detected || false,
      challengeDetected: securityLayers.challenge_detected || false,
      securityLayers: securityLayers.security_layers || []
    };
  };

  // Get vulnerability breakdown by category
  const getVulnerabilityBreakdown = () => {
    if (!report?.findings?.api) return {};
    
    const findings = report.findings.api;
    const vulnerabilities = findings.vulnerabilities || findings;
    
    const categories = {
      'Injection Attacks': ['sql_injection', 'command_injection', 'xss', 'xxe', 'ssrf'],
      'Banking Security': ['double_spending', 'race_conditions', 'privilege_escalation', 'bola_attacks', 'transaction_manipulation'],
      'Authentication': ['auth_bypass', 'session_fixation', 'jwt_attacks'],
      'Information Disclosure': ['metadata_leakage', 'verbose_errors', 'open_endpoints'],
      'Configuration': ['security_headers', 'cors', 'rate_limiting']
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
  const securityLayerInfo = getSecurityLayerInfo();
  const vulnerabilityBreakdown = getVulnerabilityBreakdown();

  // Report steps for stepper
  const reportSteps = [
    'Executive Summary',
    'Security Analysis',
    'Vulnerability Details',
    'Recommendations'
  ];

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

      {/* Enhanced Header Section */}
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
        <Grid container spacing={3} sx={{ mb: 3 }}>
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
                <ErrorIcon sx={{ fontSize: isMobile ? 40 : 50, mb: 1, opacity: 0.9 }} />
                <Typography variant={isMobile ? "h5" : "h4"} sx={{ fontWeight: 'bold' }}>
                  {metrics.total}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Total Issues
                </Typography>
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
                <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1, mb: 1, flexWrap: 'wrap' }}>
                  <Chip label={`${metrics.critical}🔴`} size="small" sx={{ color: 'white', border: '1px solid white' }} variant="outlined" />
                  <Chip label={`${metrics.high}🟠`} size="small" sx={{ color: 'white', border: '1px solid white' }} variant="outlined" />
                  <Chip label={`${metrics.medium}🟡`} size="small" sx={{ color: 'white', border: '1px solid white' }} variant="outlined" />
                </Box>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Risk Breakdown
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Security Layer Status */}
        {securityLayerInfo && (
          <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
            <CardContent sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ShieldIcon />
                Security Layer Protection Status
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>Blocked Attacks</Typography>
                  <Typography variant="h6">{securityLayerInfo.totalBlocked}</Typography>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>WAF Protection</Typography>
                  <Typography variant="h6">{securityLayerInfo.wafDetected ? '✅' : '❌'}</Typography>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>Rate Limiting</Typography>
                  <Typography variant="h6">{securityLayerInfo.rateLimitDetected ? '✅' : '❌'}</Typography>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>Auth Blocks</Typography>
                  <Typography variant="h6">{securityLayerInfo.authBlocksDetected ? '✅' : '❌'}</Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        )}
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
              startIcon={showTechnicalDetails ? <VisibilityOffIcon /> : <VisibilityIcon />}
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            >
              {showTechnicalDetails ? 'Hide' : 'Show'} Technical Details
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Vulnerability Breakdown by Category */}
      {Object.keys(vulnerabilityBreakdown).length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <TrendingUpIcon color="primary" />
            Vulnerability Analysis by Category
          </Typography>
          <Grid container spacing={2}>
            {Object.entries(vulnerabilityBreakdown).map(([category, data]: [string, any]) => {
              if (data.count === 0) return null;
              
              const categoryIcons: any = {
                'Injection Attacks': <BugIcon />,
                'Banking Security': <BankIcon />,
                'Authentication': <VpnIcon />,
                'Information Disclosure': <InfoIcon />,
                'Configuration': <SettingsIcon />
              };
              
              return (
                <Grid item xs={12} sm={6} md={4} key={category}>
                  <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      {categoryIcons[category]}
                      <Typography variant="h6">{category}</Typography>
                    </Box>
                    <Typography variant="h4" color="error" gutterBottom>
                      {data.count}
                    </Typography>
                    <List dense>
                      {data.issues.map((issue: any, index: number) => (
                        <ListItem key={index} sx={{ px: 0 }}>
                          <ListItemIcon>
                            <WarningIcon color="warning" fontSize="small" />
                          </ListItemIcon>
                          <ListItemText 
                            primary={issue.name}
                            secondary={
                              issue.details ? 
                                `${issue.count} issue${issue.count > 1 ? 's' : ''}: ${issue.details.join(', ')}` :
                                `${issue.count} issue${issue.count > 1 ? 's' : ''}`
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

      {/* Main Report Content */}
      <Paper 
        elevation={2} 
        sx={{ 
          p: isMobile ? 3 : 5, 
          minHeight: 600,
          borderRadius: 3,
          backgroundColor: '#ffffff'
        }}
      >
        <Box sx={{ mb: 3 }}>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <AssessmentIcon color="primary" />
            Detailed Security Report
          </Typography>
          <Divider />
        </Box>

        {/* Report content with enhanced markdown rendering */}
        <ReactMarkdown 
          components={{
            h1: ({ children }) => (
              <Typography variant={isMobile ? "h5" : "h4"} component="h1" sx={{ fontWeight: 'bold', mb: 3, mt: 4, color: 'primary.main' }}>
                {children}
              </Typography>
            ),
            h2: ({ children }) => (
              <Typography variant={isMobile ? "h6" : "h5"} component="h2" sx={{ fontWeight: 'bold', mb: 2, mt: 3, color: 'text.primary' }}>
                {children}
              </Typography>
            ),
            h3: ({ children }) => (
              <Typography variant="subtitle1" component="h3" sx={{ fontWeight: 'bold', mb: 2, mt: 2, color: 'text.primary' }}>
                {children}
              </Typography>
            ),
            p: ({ children }) => (
              <Typography variant="body1" paragraph sx={{ lineHeight: 1.7, mb: 2 }}>
                {children}
              </Typography>
            ),
            code: ({ node, inline, className, children, ...props }: any) => {
              const match = /language-(\w+)/.exec(className || '');
              return !inline && match ? (
                <SyntaxHighlighter
                  style={atomOneDark}
                  language={match[1]}
                  PreTag="div"
                  customStyle={{
                    borderRadius: '12px',
                    fontSize: isMobile ? '12px' : '14px',
                    padding: isMobile ? '12px' : '20px',
                    margin: '16px 0',
                    backgroundColor: '#1e1e1e',
                  }}
                  {...props}
                >
                  {String(children).replace(/\n$/, '')}
                </SyntaxHighlighter>
              ) : (
                <Box
                  component="code"
                  sx={{
                    backgroundColor: 'grey.100',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontSize: '0.85em',
                    fontFamily: 'Monaco, Consolas, monospace',
                    wordBreak: 'break-word',
                    border: '1px solid',
                    borderColor: 'grey.300'
                  }}
                  {...props}
                >
                  {children}
                </Box>
              );
            },
            table: ({ children }) => (
              <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }} elevation={1}>
                <Table size="small">
                  {children}
                </Table>
              </TableContainer>
            ),
            thead: ({ children }) => <TableHead>{children}</TableHead>,
            tbody: ({ children }) => <TableBody>{children}</TableBody>,
            tr: ({ children }) => <TableRow>{children}</TableRow>,
            th: ({ children }) => (
              <TableCell 
                sx={{
                  backgroundColor: 'primary.main',
                  color: 'white',
                  fontWeight: 'bold',
                  fontSize: '0.9rem'
                }}
              >
                {children}
              </TableCell>
            ),
            td: ({ children }) => (
              <TableCell sx={{ fontSize: '0.85rem', lineHeight: 1.4 }}>
                {children}
              </TableCell>
            ),
            blockquote: ({ children }) => (
              <Paper
                elevation={1}
                sx={{
                  p: isMobile ? 2 : 3,
                  bgcolor: 'info.light',
                  borderLeft: 6,
                  borderColor: 'info.main',
                  my: 3,
                  borderRadius: 2,
                  color: 'info.contrastText'
                }}
              >
                {children}
              </Paper>
            ),
            hr: () => <Divider sx={{ my: 4 }} />
          }}
        >
          {report.report_content}
        </ReactMarkdown>
      </Paper>

      {/* Technical Details Section */}
      <Collapse in={showTechnicalDetails}>
        <Paper elevation={1} sx={{ mt: 3, p: 3, bgcolor: 'grey.50', borderRadius: 2 }}>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CodeIcon color="primary" />
            Technical Scan Details
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
              <Typography variant="h6">Scan Metadata</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                <ListItem>
                  <ListItemIcon><InfoIcon /></ListItemIcon>
                  <ListItemText primary="Scan ID" secondary={scanId} />
                </ListItem>
                <ListItem>
                  <ListItemIcon><TimeIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Duration" 
                    secondary={`${formatDuration(report.duration)} (${report.duration}s)`} 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><RunIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Start Time" 
                    secondary={new Date(report.start_time).toLocaleString()} 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon /></ListItemIcon>
                  <ListItemText 
                    primary="End Time" 
                    secondary={new Date(report.end_time).toLocaleString()} 
                  />
                </ListItem>
              </List>
            </AccordionDetails>
          </Accordion>
        </Paper>
      </Collapse>

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
    </Container>
  );
};

export default ReportDetail; 