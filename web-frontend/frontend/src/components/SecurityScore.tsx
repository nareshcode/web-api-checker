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
} from '@mui/material';
import {
  Shield as ShieldIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
} from '@mui/icons-material';

interface SecurityScoreProps {
  scanStatus?: any;
}

const SecurityScore: React.FC<SecurityScoreProps> = ({ scanStatus }) => {
  const calculateSecurityScore = (findings: any) => {
    if (!findings || !findings.api) return 100;

    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    const api = findings.api;

    // Count vulnerabilities by severity
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

    vulnerabilityTypes.forEach((type) => {
      if (api[type] && Array.isArray(api[type]) && api[type].length > 0) {
        if (['sql_injection', 'command_injection', 'xxe', 'ssrf'].includes(type)) {
          criticalCount += api[type].length;
        } else if (['xss', 'nosql_injection', 'ldap_injection', 'path_traversal'].includes(type)) {
          highCount += api[type].length;
        }
      }
    });

    // Count security header issues (medium severity)
    if (api.security_headers) {
      Object.values(api.security_headers).forEach((headers: any) => {
        if (headers && typeof headers === 'object') {
          Object.values(headers).forEach((value) => {
            if (value === null) mediumCount++;
          });
        }
      });
    }

    // Calculate score
    const totalDeductions = criticalCount * 40 + highCount * 20 + mediumCount * 10 + lowCount * 5;
    return Math.max(0, 100 - totalDeductions);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'success';
    if (score >= 60) return 'warning';
    return 'error';
  };

  const getScoreIcon = (score: number) => {
    if (score >= 80) return <CheckIcon color="success" />;
    if (score >= 60) return <WarningIcon color="warning" />;
    return <ErrorIcon color="error" />;
  };

  const score = scanStatus?.findings && scanStatus?.status === 'completed' ? calculateSecurityScore(scanStatus.findings) : null;

  if (!scanStatus) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <ShieldIcon color="primary" />
            <Typography variant="h6">Security Score</Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Start a scan to see your security score
          </Typography>
        </CardContent>
      </Card>
    );
  }

  const findings = scanStatus.findings?.api || {};
  const criticalIssues = ['sql_injection', 'command_injection', 'xxe', 'ssrf']
    .filter((type) => findings[type] && Array.isArray(findings[type]) && findings[type].length > 0)
    .length;

  const highIssues = ['xss', 'nosql_injection', 'ldap_injection', 'path_traversal']
    .filter((type) => findings[type] && Array.isArray(findings[type]) && findings[type].length > 0)
    .length;

  let mediumIssues = 0;
  if (findings.security_headers) {
    Object.values(findings.security_headers).forEach((headers: any) => {
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
          <Typography variant="h6">Security Score</Typography>
        </Box>

        {score !== null && (
          <>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              {getScoreIcon(score)}
              <Typography 
                variant="h3" 
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
                mb: 3,
                '& .MuiLinearProgress-bar': {
                  backgroundColor: `${getScoreColor(score)}.main`
                }
              }}
            />

            <Typography variant="body2" color="text.secondary" gutterBottom>
              {score >= 80 && 'Excellent security posture!'}
              {score >= 60 && score < 80 && 'Good security with room for improvement.'}
              {score < 60 && 'Security improvements needed.'}
            </Typography>

            <Divider sx={{ my: 2 }} />

            <Typography variant="subtitle2" gutterBottom>
              Vulnerability Breakdown:
            </Typography>

            <List dense>
              <ListItem>
                <ListItemIcon>
                  <ErrorIcon color="error" />
                </ListItemIcon>
                <ListItemText
                  primary="Critical Issues"
                  secondary={criticalIssues > 0 ? `${criticalIssues} found` : 'None found'}
                />
                {criticalIssues > 0 && (
                  <Chip
                    label={criticalIssues}
                    color="error"
                    size="small"
                  />
                )}
              </ListItem>

              <ListItem>
                <ListItemIcon>
                  <WarningIcon color="warning" />
                </ListItemIcon>
                <ListItemText
                  primary="High Issues"
                  secondary={highIssues > 0 ? `${highIssues} found` : 'None found'}
                />
                {highIssues > 0 && (
                  <Chip
                    label={highIssues}
                    color="warning"
                    size="small"
                  />
                )}
              </ListItem>

              <ListItem>
                <ListItemIcon>
                  <InfoIcon color="info" />
                </ListItemIcon>
                <ListItemText
                  primary="Medium Issues"
                  secondary={mediumIssues > 0 ? `${mediumIssues} found` : 'None found'}
                />
                {mediumIssues > 0 && (
                  <Chip
                    label={mediumIssues}
                    color="info"
                    size="small"
                  />
                )}
              </ListItem>
            </List>
          </>
        )}

        {scanStatus.status === 'running' && (
          <Box sx={{ textAlign: 'center', py: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Analyzing security vulnerabilities...
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default SecurityScore; 