import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  LinearProgress,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  Alert,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Shield as ShieldIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  Security as SecurityShieldIcon,
  Gavel as ComplianceIcon,
  BugReport as VulnIcon,
} from '@mui/icons-material';

interface SecurityScoreProps {
  scanStatus?: any;
}

const SecurityScore: React.FC<SecurityScoreProps> = ({ scanStatus }) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  const calculateSecurityScore = (findings: any) => {
    if (!findings || !findings.api) return 100;

    const api = findings.api;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    // Handle new structure with vulnerabilities and security_layers
    const vulnerabilities = api.vulnerabilities || api;

    // Handle severity-based structure
    if (vulnerabilities.critical) {
      criticalCount = Array.isArray(vulnerabilities.critical) ? vulnerabilities.critical.length : 0;
    }
    if (vulnerabilities.high) {
      highCount = Array.isArray(vulnerabilities.high) ? vulnerabilities.high.length : 0;
    }
    if (vulnerabilities.medium) {
      mediumCount = Array.isArray(vulnerabilities.medium) ? vulnerabilities.medium.length : 0;
    }
    if (vulnerabilities.low) {
      lowCount = Array.isArray(vulnerabilities.low) ? vulnerabilities.low.length : 0;
    }

    // Handle legacy type-based structure
    const vulnerabilityTypes = [
      'sql_injection',
      'xss',
      'command_injection',
      'xxe',
      'ssrf',
      'nosql_injection',
      'ldap_injection',
      'path_traversal',
    ];

    if (!vulnerabilities.critical && !vulnerabilities.high) {
      vulnerabilityTypes.forEach((type) => {
        if (vulnerabilities[type] && Array.isArray(vulnerabilities[type]) && vulnerabilities[type].length > 0) {
          if (['sql_injection', 'command_injection', 'xxe', 'ssrf'].includes(type)) {
            criticalCount += vulnerabilities[type].length;
          } else if (['xss', 'nosql_injection', 'ldap_injection', 'path_traversal'].includes(type)) {
            highCount += vulnerabilities[type].length;
          }
        }
      });
    }

    // Count security header issues (medium severity)
    if (vulnerabilities.security_headers && !vulnerabilities.medium) {
      Object.values(vulnerabilities.security_headers).forEach((headers: any) => {
        if (headers && typeof headers === 'object') {
          Object.values(headers).forEach((value) => {
            if (value === null) mediumCount++;
          });
        }
      });
    }

    // Calculate score with improved algorithm
    const totalDeductions = criticalCount * 40 + highCount * 20 + mediumCount * 10 + lowCount * 5;
    return Math.max(0, 100 - totalDeductions);
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'success';
    if (score >= 70) return 'warning';
    return 'error';
  };

  const getScoreIcon = (score: number) => {
    if (score >= 90) return <CheckIcon color="success" />;
    if (score >= 70) return <WarningIcon color="warning" />;
    return <ErrorIcon color="error" />;
  };

  const getScoreDescription = (score: number) => {
    if (score >= 90) return 'Excellent security posture! API is well-protected.';
    if (score >= 70) return 'Good security with some areas for improvement.';
    if (score >= 50) return 'Moderate security - several issues need attention.';
    return 'Poor security - immediate action required.';
  };

  const getSecurityLayerInfo = (findings: any) => {
    if (!findings?.api?.security_layers) return null;

    const securityLayers = findings.api.security_layers;
    const blockedRequests = securityLayers.blocked_requests || [];

    return {
      totalBlocked: blockedRequests.length,
      wafDetected: securityLayers.waf_detected || false,
      rateLimitDetected: securityLayers.rate_limiting_detected || false,
      authBlocksDetected: securityLayers.auth_blocks_detected || false,
      captchaDetected: securityLayers.captcha_detected || false,
      challengeDetected: securityLayers.challenge_detected || false,
      protectionLayers: [
        { name: 'WAF Protection', active: securityLayers.waf_detected },
        { name: 'Rate Limiting', active: securityLayers.rate_limiting_detected },
        { name: 'Auth Blocks', active: securityLayers.auth_blocks_detected },
        { name: 'CAPTCHA', active: securityLayers.captcha_detected },
        { name: 'Challenge Response', active: securityLayers.challenge_detected },
      ].filter(layer => layer.active)
    };
  };

  const score = scanStatus?.findings && scanStatus?.status === 'completed' ? calculateSecurityScore(scanStatus.findings) : null;
  const securityLayerInfo = scanStatus?.findings ? getSecurityLayerInfo(scanStatus.findings) : null;

  if (!scanStatus) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <ShieldIcon color="primary" />
            <Typography variant="h6">Security Assessment</Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Start a scan to see your security assessment
          </Typography>
        </CardContent>
      </Card>
    );
  }

  const findings = scanStatus.findings?.api || {};
  const vulnerabilities = findings.vulnerabilities || findings;

  // Count issues by severity
  let criticalIssues = 0;
  let highIssues = 0;
  let mediumIssues = 0;

  // Handle new severity-based structure
  if (vulnerabilities.critical) {
    criticalIssues = Array.isArray(vulnerabilities.critical) ? vulnerabilities.critical.length : 0;
  }
  if (vulnerabilities.high) {
    highIssues = Array.isArray(vulnerabilities.high) ? vulnerabilities.high.length : 0;
  }
  if (vulnerabilities.medium) {
    mediumIssues = Array.isArray(vulnerabilities.medium) ? vulnerabilities.medium.length : 0;
  }

  // Handle legacy type-based structure
  if (!vulnerabilities.critical && !vulnerabilities.high) {
    const criticalTypes = ['sql_injection', 'command_injection', 'xxe', 'ssrf'];
    const highTypes = ['xss', 'nosql_injection', 'ldap_injection', 'path_traversal'];

    criticalTypes.forEach(type => {
      if (vulnerabilities[type] && Array.isArray(vulnerabilities[type])) {
        criticalIssues += vulnerabilities[type].length;
      }
    });

    highTypes.forEach(type => {
      if (vulnerabilities[type] && Array.isArray(vulnerabilities[type])) {
        highIssues += vulnerabilities[type].length;
      }
    });
  }

  // Count security header issues
  if (vulnerabilities.security_headers && !vulnerabilities.medium) {
    Object.values(vulnerabilities.security_headers).forEach((headers: any) => {
      if (headers && typeof headers === 'object') {
        Object.values(headers).forEach((value) => {
          if (value === null) mediumIssues++;
        });
      }
    });
  }

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <ShieldIcon color="primary" />
          <Typography variant="h6">Security Assessment</Typography>
        </Box>

        {score !== null && (
          <>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              {getScoreIcon(score)}
              <Typography 
                variant={isMobile ? "h4" : "h3"} 
                sx={{ color: `${getScoreColor(score)}.main` }}
              >
                {score}/100
              </Typography>
            </Box>

            <LinearProgress
              variant="determinate"
              value={score}
              sx={{ 
                height: 8, 
                borderRadius: 4, 
                mb: 2,
                '& .MuiLinearProgress-bar': {
                  backgroundColor: `${getScoreColor(score)}.main`
                }
              }}
            />

            <Typography variant="body2" color="text.secondary" gutterBottom>
              {getScoreDescription(score)}
            </Typography>

            <Divider sx={{ my: 2 }} />

            {/* Vulnerability Breakdown */}
            <Typography variant="subtitle2" gutterBottom>
              Vulnerability Assessment:
            </Typography>

            <Grid container spacing={1} sx={{ mb: 2 }}>
              <Grid item xs={4}>
                <Card variant="outlined" sx={{ p: 1, textAlign: 'center' }}>
                  <Typography variant="caption" color="text.secondary">Critical</Typography>
                  <Typography variant="h6" color={criticalIssues > 0 ? 'error.main' : 'success.main'}>
                    {criticalIssues}
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={4}>
                <Card variant="outlined" sx={{ p: 1, textAlign: 'center' }}>
                  <Typography variant="caption" color="text.secondary">High</Typography>
                  <Typography variant="h6" color={highIssues > 0 ? 'warning.main' : 'success.main'}>
                    {highIssues}
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={4}>
                <Card variant="outlined" sx={{ p: 1, textAlign: 'center' }}>
                  <Typography variant="caption" color="text.secondary">Medium</Typography>
                  <Typography variant="h6" color={mediumIssues > 0 ? 'info.main' : 'success.main'}>
                    {mediumIssues}
                  </Typography>
                </Card>
              </Grid>
            </Grid>

            {/* Security Layer Information */}
            {securityLayerInfo && (
              <>
                <Divider sx={{ my: 2 }} />
                <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SecurityShieldIcon />
                  Protection Layers:
                </Typography>

                {securityLayerInfo.totalBlocked > 0 && (
                  <Alert severity="success" sx={{ mb: 2 }}>
                    🛡️ Security layers blocked {securityLayerInfo.totalBlocked} attack attempts!
                  </Alert>
                )}

                <List dense>
                  {securityLayerInfo.protectionLayers.map((layer, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <CheckIcon color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary={layer.name}
                        secondary="Active and protecting your API"
                      />
                    </ListItem>
                  ))}
                  
                  {securityLayerInfo.protectionLayers.length === 0 && (
                    <ListItem>
                      <ListItemIcon>
                        <InfoIcon color="info" />
                      </ListItemIcon>
                      <ListItemText
                        primary="No security layers detected"
                        secondary="Consider implementing WAF, rate limiting, or other protection mechanisms"
                      />
                    </ListItem>
                  )}
                </List>
              </>
            )}

            {/* Detailed Vulnerability List */}
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle2" gutterBottom>
              Detailed Security Status:
            </Typography>

            <List dense>
              {/* HTTPS Status */}
              <ListItem>
                <ListItemIcon>
                  {vulnerabilities.https ? <CheckIcon color="success" /> : <ErrorIcon color="error" />}
                </ListItemIcon>
                <ListItemText
                  primary="HTTPS Encryption"
                  secondary={vulnerabilities.https ? 'Transport encryption enabled' : 'Missing HTTPS - data transmitted in plain text'}
                />
              </ListItem>

              {/* Authentication */}
              {!vulnerabilities.open_endpoints || vulnerabilities.open_endpoints.length === 0 ? (
                <ListItem>
                  <ListItemIcon>
                    <CheckIcon color="success" />
                  </ListItemIcon>
                  <ListItemText
                    primary="Authentication Controls"
                    secondary="All endpoints require proper authentication"
                  />
                </ListItem>
              ) : (
                <ListItem>
                  <ListItemIcon>
                    <ErrorIcon color="error" />
                  </ListItemIcon>
                  <ListItemText
                    primary="Open Endpoints"
                    secondary={`${vulnerabilities.open_endpoints.length} endpoints accessible without authentication`}
                  />
                </ListItem>
              )}

              {/* Major Vulnerabilities */}
              {['sql_injection', 'xss', 'command_injection', 'xxe'].map(vulnType => {
                const hasVuln = vulnerabilities[vulnType] && Array.isArray(vulnerabilities[vulnType]) && vulnerabilities[vulnType].length > 0;
                return (
                  <ListItem key={vulnType}>
                    <ListItemIcon>
                      {hasVuln ? <ErrorIcon color="error" /> : <CheckIcon color="success" />}
                    </ListItemIcon>
                    <ListItemText
                      primary={vulnType.replace('_', ' ').toUpperCase() + ' Protection'}
                      secondary={hasVuln 
                        ? `${vulnerabilities[vulnType].length} vulnerabilities found`
                        : `Protected against ${vulnType.replace('_', ' ')} attacks`
                      }
                    />
                  </ListItem>
                );
              })}
            </List>
          </>
        )}

        {scanStatus.status === 'running' && (
          <Box sx={{ textAlign: 'center', py: 2 }}>
            <VulnIcon color="primary" sx={{ fontSize: 40, mb: 1 }} />
            <Typography variant="body2" color="text.secondary">
              Analyzing security vulnerabilities...
            </Typography>
            <LinearProgress sx={{ mt: 2 }} />
          </Box>
        )}

        {scanStatus.status === 'error' && (
          <Alert severity="error">
            Scan failed. Please try again or check the target URL.
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};

export default SecurityScore; 