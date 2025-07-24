import React, { useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Alert,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Paper,
  Button,
  TextField,
  InputAdornment,
  Tabs,
  Tab,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Code as CodeIcon,
  BugReport as BugIcon,
  Search as SearchIcon,
  AssignmentTurnedIn as TestIcon,
  Language as WebIcon,
  AccountBalance as BankIcon,
  Storage as DataIcon,
  VpnLock as NetworkIcon,
  SettingsApplications as ConfigIcon,
} from '@mui/icons-material';
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomOneDark } from 'react-syntax-highlighter/dist/esm/styles/hljs';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`security-tabpanel-${index}`}
      aria-labelledby={`security-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

// Comprehensive security test data based on api_scanner.py
const SECURITY_TESTS = {
  critical: [
    {
      id: 'https_check',
      name: 'HTTPS Implementation',
      category: 'Infrastructure Security',
      icon: <NetworkIcon color="error" />,
      description: 'Validates that the API uses HTTPS encryption for all communications to prevent man-in-the-middle attacks and data interception.',
      whatWeTesting: 'Checking if the API endpoint uses HTTPS protocol and properly implements TLS/SSL encryption.',
      howItWorks: 'We analyze the URL scheme and attempt connections to verify secure transport layer implementation.',
      examples: [
        {
          type: 'Vulnerable',
          code: 'http://api.example.com/users',
          description: 'Unencrypted HTTP connection exposing all data in transit'
        },
        {
          type: 'Secure',
          code: 'https://api.example.com/users',
          description: 'Properly encrypted HTTPS connection with TLS/SSL'
        }
      ],
      attackScenarios: [
        'Man-in-the-middle attacks intercepting credentials',
        'Packet sniffing to capture sensitive data',
        'Session hijacking through unencrypted connections',
        'Data tampering during transmission'
      ],
      references: [
        'OWASP API Security Top 10 - API7:2023 Server Side Request Forgery',
        'RFC 2818 - HTTP Over TLS',
        'NIST SP 800-52 - Guidelines for TLS Implementation'
      ],
      cvssScore: 7.4,
      impact: 'Complete data interception and manipulation possible'
    },
    {
      id: 'sql_injection',
      name: 'SQL Injection Testing',
      category: 'Injection Attacks',
      icon: <DataIcon color="error" />,
      description: 'Tests for SQL injection vulnerabilities that could allow attackers to manipulate database queries and access unauthorized data.',
      whatWeTesting: 'Input validation, parameterized queries, and database interaction security.',
      howItWorks: 'We inject malicious SQL payloads into URL parameters and request bodies to test if they are executed by the database.',
      examples: [
        {
          type: 'Attack Payload',
          code: "'; DROP TABLE users;--",
          description: 'Attempts to delete the entire users table'
        },
        {
          type: 'Attack Payload',
          code: "' OR 1=1--",
          description: 'Bypasses authentication by making condition always true'
        },
        {
          type: 'Attack Payload',
          code: "' UNION SELECT password FROM users--",
          description: 'Attempts to extract password data from users table'
        }
      ],
      testPayloads: [
        "'; DROP TABLE users;--",
        "' OR 1=1--",
        "' OR '1'='1",
        "'; WAITFOR DELAY '00:00:05'--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
      ],
      attackScenarios: [
        'Complete database compromise and data theft',
        'User authentication bypass',
        'Administrative privilege escalation',
        'Data modification or deletion',
        'Server takeover through stored procedures'
      ],
      references: [
        'OWASP API Security Top 10 - API8:2023 Security Misconfiguration',
        'CWE-89: SQL Injection',
        'SANS Top 25 Most Dangerous Software Errors'
      ],
      cvssScore: 9.8,
      impact: 'Complete database compromise possible'
    },
    {
      id: 'command_injection',
      name: 'Command Injection Testing',
      category: 'Injection Attacks',
      icon: <CodeIcon color="error" />,
      description: 'Tests for command injection vulnerabilities that allow attackers to execute arbitrary system commands on the server.',
      whatWeTesting: 'Input sanitization, command execution security, and system call validation.',
      howItWorks: 'We inject shell commands and metacharacters to test if user input is passed to system commands without proper validation.',
      examples: [
        {
          type: 'Attack Payload',
          code: '; ls -la',
          description: 'Lists directory contents on Unix systems'
        },
        {
          type: 'Attack Payload',
          code: '| whoami',
          description: 'Reveals the current system user'
        },
        {
          type: 'Attack Payload',
          code: '& cat /etc/passwd',
          description: 'Attempts to read system password file'
        }
      ],
      testPayloads: [
        '; ls -la',
        '| whoami',
        '& cat /etc/passwd',
        '; id',
        '| uname -a',
        '& ps aux',
        '; pwd',
        '| hostname'
      ],
      attackScenarios: [
        'Complete server compromise and control',
        'File system access and data theft',
        'Network reconnaissance from compromised server',
        'Privilege escalation to root/administrator',
        'Installation of backdoors and malware'
      ],
      references: [
        'OWASP API Security Top 10 - API8:2023 Security Misconfiguration',
        'CWE-78: OS Command Injection',
        'MITRE ATT&CK - T1059 Command and Scripting Interpreter'
      ],
      cvssScore: 9.8,
      impact: 'Server takeover and system compromise'
    },
    {
      id: 'double_spending',
      name: 'Double Spending Protection',
      category: 'Banking Security',
      icon: <BankIcon color="error" />,
      description: 'Tests for double spending vulnerabilities in financial transactions that could allow spending the same money multiple times.',
      whatWeTesting: 'Transaction idempotency, concurrency controls, and financial integrity mechanisms.',
      howItWorks: 'We send identical transaction requests rapidly to test if the system prevents duplicate transactions.',
      examples: [
        {
          type: 'Attack Payload',
          code: '{"amount": 1000, "to_account": "1234567890", "idempotency_key": "duplicate_key_123"}',
          description: 'Attempts to replay the same transaction multiple times'
        },
        {
          type: 'Attack Payload',
          code: '{"amount": 1000, "to_account": "1234567890", "transaction_id": "replay_attack_456"}',
          description: 'Uses duplicate transaction ID to bypass controls'
        }
      ],
      testPayloads: [
        '{"amount": 1000, "to_account": "1234567890", "idempotency_key": "duplicate_key_123"}',
        '{"amount": 1000, "to_account": "1234567890", "transaction_id": "replay_attack_456"}',
        '{"amount": 1000, "to_account": "1234567890", "timestamp": "2023-01-01T00:00:00Z"}'
      ],
      attackScenarios: [
        'Fraudulent money multiplication through duplicate transactions',
        'Account balance manipulation and theft',
        'Payment system exploitation for financial gain',
        'Race condition exploitation during high-value transfers'
      ],
      references: [
        'OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption',
        'PCI DSS Requirements for Transaction Processing',
        'Financial Industry Cybersecurity Framework'
      ],
      cvssScore: 9.1,
      impact: 'Financial fraud and monetary theft'
    },
    {
      id: 'race_conditions',
      name: 'Race Condition Testing',
      category: 'Banking Security',
      icon: <BankIcon color="error" />,
      description: 'Tests for race condition vulnerabilities in concurrent financial operations that could lead to inconsistent data states.',
      whatWeTesting: 'Concurrency controls, atomic operations, and transaction isolation.',
      howItWorks: 'We send multiple concurrent requests to test if the system maintains data consistency under high load.',
      examples: [
        {
          type: 'Attack Scenario',
          code: 'Multiple simultaneous withdrawals from same account',
          description: 'Could allow overdrafts beyond account limits'
        },
        {
          type: 'Attack Payload',
          code: '{"amount": 999999, "account_id": "race_condition_test"}',
          description: 'Large transaction amount to exploit timing windows'
        }
      ],
      attackScenarios: [
        'Account overdrafts beyond available balance',
        'Concurrent loan approvals exceeding limits',
        'Simultaneous access to shared resources',
        'Data corruption in high-frequency trading'
      ],
      references: [
        'OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption',
        'CWE-362: Concurrent Execution using Shared Resource',
        'Banking Industry Security Standards'
      ],
      cvssScore: 8.8,
      impact: 'Financial inconsistencies and fraud'
    }
  ],
  high: [
    {
      id: 'xss',
      name: 'Cross-Site Scripting (XSS)',
      category: 'Web Security',
      icon: <WebIcon color="warning" />,
      description: 'Tests for XSS vulnerabilities that allow injection of malicious scripts into web applications.',
      whatWeTesting: 'Input validation, output encoding, and client-side security controls.',
      howItWorks: 'We inject JavaScript payloads to test if they are executed in the browser or reflected in responses.',
      examples: [
        {
          type: 'Attack Payload',
          code: "<script>alert('XSS')</script>",
          description: 'Basic script injection to execute JavaScript'
        },
        {
          type: 'Attack Payload',
          code: "<img src=x onerror=alert('XSS')>",
          description: 'Image tag with error handler for script execution'
        },
        {
          type: 'Attack Payload',
          code: "<svg onload=alert('XSS')>",
          description: 'SVG element with onload event for script execution'
        }
      ],
      testPayloads: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>"
      ],
      attackScenarios: [
        'Session hijacking through cookie theft',
        'Keylogging and credential harvesting',
        'Phishing attacks and user redirection',
        'Account takeover and impersonation',
        'Malware distribution to users'
      ],
      references: [
        'OWASP API Security Top 10 - API8:2023 Security Misconfiguration',
        'CWE-79: Cross-site Scripting',
        'OWASP XSS Prevention Cheat Sheet'
      ],
      cvssScore: 7.2,
      impact: 'Session hijacking and user impersonation'
    },
    {
      id: 'transaction_manipulation',
      name: 'Transaction Manipulation',
      category: 'Banking Security',
      icon: <BankIcon color="warning" />,
      description: 'Tests for vulnerabilities in transaction processing that allow manipulation of financial data.',
      whatWeTesting: 'Transaction validation, amount verification, and business logic controls.',
      howItWorks: 'We send transactions with invalid amounts, negative values, and edge cases to test validation.',
      examples: [
        {
          type: 'Attack Payload',
          code: '{"amount": -1000, "to_account": "1234567890"}',
          description: 'Negative amount to potentially credit money'
        },
        {
          type: 'Attack Payload',
          code: '{"amount": 0.01, "to_account": "1234567890"}',
          description: 'Micro-transaction to test limits'
        },
        {
          type: 'Attack Payload',
          code: '{"amount": null, "to_account": "1234567890"}',
          description: 'Null amount to bypass validation'
        }
      ],
      attackScenarios: [
        'Negative amount transactions to create money',
        'Decimal precision attacks for rounding errors',
        'Overflow attacks with extremely large numbers',
        'Business logic bypass for transaction limits'
      ],
      references: [
        'OWASP API Security Top 10 - API10:2023 Unsafe Consumption of APIs',
        'PCI DSS Payment Processing Requirements',
        'Financial Services Security Guidelines'
      ],
      cvssScore: 7.5,
      impact: 'Financial manipulation and fraud'
    },
    {
      id: 'privilege_escalation',
      name: 'Privilege Escalation Testing',
      category: 'Authentication & Authorization',
      icon: <ShieldIcon color="warning" />,
      description: 'Tests for vulnerabilities that allow users to gain elevated privileges beyond their authorized level.',
      whatWeTesting: 'Role-based access controls, permission validation, and authorization mechanisms.',
      howItWorks: 'We attempt to access admin functions, modify user roles, and bypass permission checks.',
      examples: [
        {
          type: 'Attack Payload',
          code: '{"user_id": "admin", "role": "super_admin"}',
          description: 'Attempts to elevate user to admin role'
        },
        {
          type: 'Attack Payload',
          code: '{"user_id": "123", "permissions": ["read", "write", "delete", "admin"]}',
          description: 'Tries to grant administrative permissions'
        }
      ],
      attackScenarios: [
        'Normal user gaining admin access',
        'Unauthorized access to sensitive functions',
        'Role manipulation for system control',
        'Permission bypass for restricted operations'
      ],
      references: [
        'OWASP API Security Top 10 - API5:2023 Broken Function Level Authorization',
        'CWE-269: Improper Privilege Management',
        'NIST Cybersecurity Framework - Access Control'
      ],
      cvssScore: 8.2,
      impact: 'Unauthorized access to admin functions'
    }
  ],
  medium: [
    {
      id: 'security_headers',
      name: 'Security Headers Analysis',
      category: 'Configuration Security',
      icon: <ConfigIcon color="info" />,
      description: 'Validates the presence and configuration of security headers that protect against various client-side attacks.',
      whatWeTesting: 'HTTP security headers implementation and proper configuration.',
      howItWorks: 'We analyze HTTP response headers to identify missing or misconfigured security controls.',
      examples: [
        {
          type: 'Missing Header',
          code: 'Content-Security-Policy',
          description: 'Prevents XSS and code injection attacks'
        },
        {
          type: 'Missing Header',
          code: 'X-Frame-Options',
          description: 'Prevents clickjacking attacks'
        },
        {
          type: 'Missing Header',
          code: 'Strict-Transport-Security',
          description: 'Enforces HTTPS connections'
        }
      ],
      testHeaders: [
        'Content-Security-Policy',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy',
        'X-XSS-Protection'
      ],
      attackScenarios: [
        'Clickjacking attacks on embedded content',
        'Content type sniffing vulnerabilities',
        'Cross-origin data leakage',
        'Browser-based security bypasses'
      ],
      references: [
        'OWASP Secure Headers Project',
        'Mozilla Security Headers Documentation',
        'RFC 7034 - HTTP Header Field X-Frame-Options'
      ],
      cvssScore: 5.4,
      impact: 'Various client-side attacks possible'
    },
    {
      id: 'metadata_leakage',
      name: 'Metadata Leakage Detection',
      category: 'Information Disclosure',
      icon: <InfoIcon color="info" />,
      description: 'Identifies sensitive information leaked in responses, headers, and error messages.',
      whatWeTesting: 'Information disclosure, debug data exposure, and metadata security.',
      howItWorks: 'We analyze responses for sensitive information like internal IPs, file paths, and system details.',
      examples: [
        {
          type: 'Sensitive Data',
          code: 'Server: Apache/2.4.41 (Ubuntu)',
          description: 'Server version information in headers'
        },
        {
          type: 'Sensitive Data',
          code: '{"internal_ip": "192.168.1.100"}',
          description: 'Internal network information in response'
        },
        {
          type: 'Sensitive Data',
          code: 'Stack trace: at /home/user/app/src/main.py:42',
          description: 'File path information in error messages'
        }
      ],
      attackScenarios: [
        'System reconnaissance for targeted attacks',
        'Internal network mapping and exploitation',
        'Version-specific vulnerability exploitation',
        'Social engineering with leaked information'
      ],
      references: [
        'OWASP API Security Top 10 - API9:2023 Improper Inventory Management',
        'CWE-200: Information Exposure',
        'NIST SP 800-53 - Information System Monitoring'
      ],
      cvssScore: 4.3,
      impact: 'System information leakage'
    },
    {
      id: 'rate_limiting',
      name: 'Rate Limiting Analysis',
      category: 'Performance & Security',
      icon: <NetworkIcon color="info" />,
      description: 'Tests for rate limiting controls that prevent abuse and denial of service attacks.',
      whatWeTesting: 'Request throttling, API usage limits, and abuse prevention mechanisms.',
      howItWorks: 'We send rapid sequential requests to test if the system implements proper rate limiting.',
      examples: [
        {
          type: 'Attack Pattern',
          code: '100 requests per second',
          description: 'High-frequency requests to overwhelm the system'
        },
        {
          type: 'Expected Response',
          code: 'HTTP 429 Too Many Requests',
          description: 'Proper rate limiting response'
        }
      ],
      attackScenarios: [
        'Denial of service through request flooding',
        'Resource exhaustion attacks',
        'Brute force attacks on authentication',
        'API abuse for competitive advantage'
      ],
      references: [
        'OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption',
        'RFC 6585 - Additional HTTP Status Codes',
        'API Security Best Practices - Rate Limiting'
      ],
      cvssScore: 5.2,
      impact: 'Denial of service and abuse'
    }
  ]
};

const SECURITY_CATEGORIES = [
  { id: 'all', name: 'All Tests', icon: <SecurityIcon />, count: Object.values(SECURITY_TESTS).flat().length },
  { id: 'injection', name: 'Injection Attacks', icon: <BugIcon />, count: 5 },
  { id: 'banking', name: 'Banking Security', icon: <BankIcon />, count: 8 },
  { id: 'web', name: 'Web Security', icon: <WebIcon />, count: 4 },
  { id: 'auth', name: 'Authentication', icon: <ShieldIcon />, count: 6 },
  { id: 'config', name: 'Configuration', icon: <ConfigIcon />, count: 3 },
];

const SecurityWiki: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [tabValue, setTabValue] = useState(0);
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  // Filter tests based on search and category
  const filterTests = (tests: any[]) => {
    return tests.filter(test => {
      const matchesSearch = searchTerm === '' || 
        test.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        test.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        test.category.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesCategory = selectedCategory === 'all' || 
        test.category.toLowerCase().includes(selectedCategory) ||
        (selectedCategory === 'injection' && ['sql_injection', 'command_injection', 'xss'].includes(test.id)) ||
        (selectedCategory === 'banking' && test.category === 'Banking Security') ||
        (selectedCategory === 'web' && test.category === 'Web Security') ||
        (selectedCategory === 'auth' && test.category === 'Authentication & Authorization') ||
        (selectedCategory === 'config' && test.category === 'Configuration Security');
      
      return matchesSearch && matchesCategory;
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      default: return 'default';
    }
  };

  const getCVSSColor = (score: number) => {
    if (score >= 9.0) return 'error';
    if (score >= 7.0) return 'warning';
    if (score >= 4.0) return 'info';
    return 'success';
  };

  const renderTestCard = (test: any, severity: string) => (
    <Card key={test.id} sx={{ mb: 2, border: `2px solid ${theme.palette[getSeverityColor(severity) as 'error' | 'warning' | 'info'].light}` }}>
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
            {test.icon}
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="h6" component="div">
                {test.name}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
                <Chip
                  label={severity.toUpperCase()}
                  color={getSeverityColor(severity)}
                  size="small"
                />
                <Chip
                  label={`CVSS: ${test.cvssScore}`}
                  color={getCVSSColor(test.cvssScore)}
                  size="small"
                />
                <Chip
                  label={test.category}
                  variant="outlined"
                  size="small"
                />
              </Box>
            </Box>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            {/* Overview */}
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom color="primary">
                📋 Test Overview
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Description:</strong> {test.description}
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>What We're Testing:</strong> {test.whatWeTesting}
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>How It Works:</strong> {test.howItWorks}
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Business Impact:</strong> {test.impact}
              </Typography>
            </Grid>

            {/* Examples */}
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom color="primary">
                🎯 Attack Examples
              </Typography>
              {test.examples?.map((example: any, index: number) => (
                <Paper key={index} sx={{ p: 2, mb: 2, bgcolor: 'grey.50' }}>
                  <Typography variant="subtitle2" color="error" gutterBottom>
                    {example.type}
                  </Typography>
                  <SyntaxHighlighter
                    language={example.type.includes('Payload') ? 'javascript' : 'bash'}
                    style={atomOneDark}
                    customStyle={{
                      borderRadius: '8px',
                      fontSize: '12px',
                      margin: '8px 0'
                    }}
                  >
                    {example.code}
                  </SyntaxHighlighter>
                  <Typography variant="caption" color="text.secondary">
                    {example.description}
                  </Typography>
                </Paper>
              ))}
            </Grid>

            {/* Test Payloads */}
            {test.testPayloads && (
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom color="primary">
                  🧪 Test Payloads
                </Typography>
                <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                  <Typography variant="body2" gutterBottom>
                    The following payloads are used to test for this vulnerability:
                  </Typography>
                  <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                    <List dense>
                      {test.testPayloads.map((payload: string, index: number) => (
                        <ListItem key={index}>
                          <ListItemIcon>
                            <CodeIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Typography
                                variant="body2"
                                sx={{
                                  fontFamily: 'monospace',
                                  fontSize: '0.8rem',
                                  bgcolor: 'rgba(0,0,0,0.1)',
                                  p: 0.5,
                                  borderRadius: 1
                                }}
                              >
                                {payload}
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                </Paper>
              </Grid>
            )}

            {/* Attack Scenarios */}
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom color="error">
                ⚠️ Attack Scenarios
              </Typography>
              <List dense>
                {test.attackScenarios?.map((scenario: string, index: number) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <WarningIcon color="error" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText
                      primary={scenario}
                      primaryTypographyProps={{ variant: 'body2' }}
                    />
                  </ListItem>
                ))}
              </List>
            </Grid>

            {/* References */}
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom color="info">
                📚 References & Standards
              </Typography>
              <List dense>
                {test.references?.map((ref: string, index: number) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <InfoIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText
                      primary={ref}
                      primaryTypographyProps={{ variant: 'body2' }}
                    />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>
    </Card>
  );

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      {/* Header */}
      <Paper elevation={3} sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: 'primary.dark', color: 'white' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <SecurityIcon sx={{ fontSize: 40 }} />
          <Box>
            <Typography variant={isMobile ? "h4" : "h3"} component="h1" gutterBottom>
              🛡️ Security Testing Wiki
            </Typography>
            <Typography variant="h6" sx={{ opacity: 0.9 }}>
              Comprehensive guide to API security testing rules and methodologies
            </Typography>
          </Box>
        </Box>
        
        <Alert severity="info" sx={{ mt: 3, bgcolor: 'rgba(255,255,255,0.1)', color: 'white' }}>
          <Typography variant="body2">
            This wiki documents all security tests performed by our API scanner. Each test includes detailed explanations, 
            attack examples, and references to industry standards. Use this as a reference for understanding 
            vulnerabilities and implementing proper security controls.
          </Typography>
        </Alert>
      </Paper>

      {/* Search and Filters */}
      <Paper elevation={2} sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexDirection: isMobile ? 'column' : 'row' }}>
          <TextField
            fullWidth
            placeholder="Search security tests..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />
        </Box>
        
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {SECURITY_CATEGORIES.map((category) => (
            <Chip
              key={category.id}
              icon={category.icon}
              label={`${category.name} (${category.count})`}
              onClick={() => setSelectedCategory(category.id)}
              color={selectedCategory === category.id ? 'primary' : 'default'}
              variant={selectedCategory === category.id ? 'filled' : 'outlined'}
            />
          ))}
        </Box>
      </Paper>

      {/* Content Tabs */}
      <Paper elevation={2} sx={{ borderRadius: 2 }}>
        <Tabs 
          value={tabValue} 
          onChange={(e, newValue) => setTabValue(newValue)}
          variant={isMobile ? "scrollable" : "fullWidth"}
          scrollButtons="auto"
        >
          <Tab 
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ErrorIcon color="error" />
                Critical ({filterTests(SECURITY_TESTS.critical).length})
              </Box>
            } 
          />
          <Tab 
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <WarningIcon color="warning" />
                High ({filterTests(SECURITY_TESTS.high).length})
              </Box>
            } 
          />
          <Tab 
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <InfoIcon color="info" />
                Medium ({filterTests(SECURITY_TESTS.medium).length})
              </Box>
            } 
          />
          <Tab 
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <TestIcon />
                Testing Guide
              </Box>
            } 
          />
        </Tabs>

        {/* Critical Tests */}
        <TabPanel value={tabValue} index={0}>
          <Alert severity="error" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Critical vulnerabilities</strong> require immediate attention and can lead to complete system compromise.
              These tests check for the most severe security flaws that could result in data breaches, financial loss, or complete system takeover.
            </Typography>
          </Alert>
          {filterTests(SECURITY_TESTS.critical).map(test => renderTestCard(test, 'critical'))}
        </TabPanel>

        {/* High Priority Tests */}
        <TabPanel value={tabValue} index={1}>
          <Alert severity="warning" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>High priority vulnerabilities</strong> pose significant security risks and should be addressed within 7 days.
              These vulnerabilities can lead to unauthorized access, data theft, or service disruption.
            </Typography>
          </Alert>
          {filterTests(SECURITY_TESTS.high).map(test => renderTestCard(test, 'high'))}
        </TabPanel>

        {/* Medium Priority Tests */}
        <TabPanel value={tabValue} index={2}>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Medium priority vulnerabilities</strong> should be addressed within 30 days.
              While not immediately critical, these issues can contribute to a weakened security posture.
            </Typography>
          </Alert>
          {filterTests(SECURITY_TESTS.medium).map(test => renderTestCard(test, 'medium'))}
        </TabPanel>

        {/* Testing Guide */}
        <TabPanel value={tabValue} index={3}>
          <Typography variant="h5" gutterBottom color="primary">
            🧪 Security Testing Methodology
          </Typography>
          
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card sx={{ p: 3, height: '100%' }}>
                <Typography variant="h6" gutterBottom>
                  🎯 Testing Approach
                </Typography>
                <List>
                  <ListItem>
                    <ListItemText 
                      primary="1. Automated Payload Injection"
                      secondary="We inject various attack payloads into URL parameters, headers, and request bodies"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="2. Response Analysis"
                      secondary="Analyze responses for vulnerability indicators, error messages, and behavioral changes"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="3. False Positive Filtering"
                      secondary="Advanced validation to distinguish real vulnerabilities from WAF blocks"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="4. Security Layer Detection"
                      secondary="Identify protective measures like WAF, rate limiting, and authentication blocks"
                    />
                  </ListItem>
                </List>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ p: 3, height: '100%' }}>
                <Typography variant="h6" gutterBottom>
                  📊 Severity Levels
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <ErrorIcon color="error" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Critical (CVSS 9.0-10.0)"
                      secondary="Immediate system compromise possible"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="High (CVSS 7.0-8.9)"
                      secondary="Significant security risk requiring urgent attention"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <InfoIcon color="info" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Medium (CVSS 4.0-6.9)"
                      secondary="Moderate risk requiring timely remediation"
                    />
                  </ListItem>
                </List>
              </Card>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: 'grey.50' }}>
                <Typography variant="h6" gutterBottom>
                  🔬 Advanced Testing Features
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={4}>
                    <Card variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <ShieldIcon color="primary" sx={{ fontSize: 40, mb: 1 }} />
                      <Typography variant="subtitle1" gutterBottom>
                        Security Layer Detection
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Automatically detects WAF, rate limiting, CAPTCHA, and other protective measures
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={4}>
                    <Card variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <BankIcon color="primary" sx={{ fontSize: 40, mb: 1 }} />
                      <Typography variant="subtitle1" gutterBottom>
                        Banking-Specific Tests
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Specialized tests for financial APIs including double spending and race conditions
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={4}>
                    <Card variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <BugIcon color="primary" sx={{ fontSize: 40, mb: 1 }} />
                      <Typography variant="subtitle1" gutterBottom>
                        False Positive Filtering
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Advanced algorithms to distinguish real vulnerabilities from security controls
                      </Typography>
                    </Card>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>
    </Container>
  );
};

export default SecurityWiki; 