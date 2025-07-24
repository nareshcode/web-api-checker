import React, { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Chip,
  Button,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  Grid,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  TableContainer,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  TablePagination,
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Toolbar,
  useTheme,
  useMediaQuery,
  Fade,
  Zoom,
  Tooltip,
  Menu,
  MenuList,
  ListItemButton,
  Divider,
  Stack,
  Avatar,
  Badge,
} from '@mui/material';
import {
  History as HistoryIcon,
  Visibility as ViewIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  PlayArrow as RunningIcon,
  Refresh as RefreshIcon,
  Dashboard as DashboardIcon,
  FilterList as FilterIcon,
  Sort as SortIcon,
  Search as SearchIcon,
  Download as DownloadIcon,
  DeleteOutline as DeleteIcon,
  MoreVert as MoreIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  TrendingUp as TrendingUpIcon,
  Schedule as ScheduleIcon,
  BugReport as BugIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Speed as SpeedIcon,
  CalendarToday as CalendarIcon,
  AccessTime as TimeIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { scanAPI } from '../utils/apiClient';

interface Scan {
  scan_id: string;
  status: string;
  progress: number;
  start_time: string;
  end_time?: string;
  current_step?: string;
  error?: string;
  findings?: any;
  duration?: number;
}

interface ScanStats {
  total: number;
  completed: number;
  running: number;
  failed: number;
  totalIssues: number;
  avgDuration: number;
}

const ScanHistory: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [filteredScans, setFilteredScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [dateFilter, setDateFilter] = useState('all');
  const [sortBy, setSortBy] = useState('start_time');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await scanAPI.listScans();
      const scanData = response.data.scans || [];
      setScans(scanData);
      setFilteredScans(scanData);
      setError('');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  // Enhanced filtering and searching
  useEffect(() => {
    let filtered = [...scans];

    // Search filter
    if (searchQuery) {
      filtered = filtered.filter(scan =>
        scan.scan_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.current_step?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.error?.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Status filter
    if (statusFilter !== 'all') {
      filtered = filtered.filter(scan => scan.status === statusFilter);
    }

    // Date filter
    if (dateFilter !== 'all') {
      const now = new Date();
      const filterDate = new Date();
      
      switch (dateFilter) {
        case 'today':
          filterDate.setHours(0, 0, 0, 0);
          break;
        case 'week':
          filterDate.setDate(now.getDate() - 7);
          break;
        case 'month':
          filterDate.setMonth(now.getMonth() - 1);
          break;
      }
      
      if (dateFilter !== 'all') {
        filtered = filtered.filter(scan => 
          new Date(scan.start_time) >= filterDate
        );
      }
    }

    // Sorting
    filtered.sort((a, b) => {
      let aValue, bValue;
      
      switch (sortBy) {
        case 'start_time':
          aValue = new Date(a.start_time).getTime();
          bValue = new Date(b.start_time).getTime();
          break;
        case 'duration':
          aValue = a.duration || 0;
          bValue = b.duration || 0;
          break;
        case 'status':
          aValue = a.status;
          bValue = b.status;
          break;
        default:
          aValue = a.scan_id;
          bValue = b.scan_id;
      }

      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

    setFilteredScans(filtered);
    setPage(0); // Reset pagination when filters change
  }, [scans, searchQuery, statusFilter, dateFilter, sortBy, sortOrder]);

  // Calculate statistics
  const getStats = (): ScanStats => {
    const total = scans.length;
    const completed = scans.filter(s => s.status === 'completed').length;
    const running = scans.filter(s => s.status === 'running').length;
    const failed = scans.filter(s => s.status === 'error').length;
    
    let totalIssues = 0;
    let totalDuration = 0;
    let validDurations = 0;

    scans.forEach(scan => {
      if (scan.findings?.api) {
        const findings = scan.findings.api;
        const vulnerabilities = findings.vulnerabilities || findings;
        
        // Count issues from different structures
        if (vulnerabilities.critical) totalIssues += vulnerabilities.critical.length;
        if (vulnerabilities.high) totalIssues += vulnerabilities.high.length;
        if (vulnerabilities.medium) totalIssues += vulnerabilities.medium.length;
        if (vulnerabilities.low) totalIssues += vulnerabilities.low.length;
      }
      
      if (scan.duration) {
        totalDuration += scan.duration;
        validDurations++;
      }
    });

    return {
      total,
      completed,
      running,
      failed,
      totalIssues,
      avgDuration: validDurations > 0 ? Math.round(totalDuration / validDurations) : 0
    };
  };

  const stats = getStats();

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'error':
        return 'error';
      case 'running':
        return 'primary';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckIcon color="success" />;
      case 'error':
        return <ErrorIcon color="error" />;
      case 'running':
        return <RunningIcon color="primary" />;
      default:
        return <HistoryIcon />;
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return {
      date: date.toLocaleDateString(),
      time: date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      relative: getRelativeTime(date)
    };
  };

  const getRelativeTime = (date: Date) => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const getDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const duration = Math.round((end.getTime() - start.getTime()) / 1000);
    
    if (duration < 60) return `${duration}s`;
    if (duration < 3600) return `${Math.round(duration / 60)}m`;
    return `${Math.round(duration / 3600)}h`;
  };

  const getScanSecurityScore = (scan: Scan) => {
    if (!scan.findings?.api) return null;
    
    const findings = scan.findings.api;
    const vulnerabilities = findings.vulnerabilities || findings;
    
    let critical = 0, high = 0, medium = 0, low = 0;
    
    if (vulnerabilities.critical) critical = vulnerabilities.critical.length;
    if (vulnerabilities.high) high = vulnerabilities.high.length;
    if (vulnerabilities.medium) medium = vulnerabilities.medium.length;
    if (vulnerabilities.low) low = vulnerabilities.low.length;
    
    const score = Math.max(0, 100 - (critical * 40 + high * 20 + medium * 10 + low * 5));
    return { score, critical, high, medium, low, total: critical + high + medium + low };
  };

  const handleViewReport = (scanId: string) => {
    navigate(`/report/${scanId}`);
  };

  const handleDeleteScan = async (scanId: string) => {
    try {
      // This would require implementing a delete endpoint
      console.log('Delete scan:', scanId);
    } catch (err) {
      console.error('Failed to delete scan:', err);
    }
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, scanId: string) => {
    setMenuAnchor(event.currentTarget);
    setSelectedScan(scanId);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
    setSelectedScan(null);
  };

  const ScanCard: React.FC<{ scan: Scan }> = ({ scan }) => {
    const securityScore = getScanSecurityScore(scan);
    const dateInfo = formatDate(scan.start_time);

    return (
      <Zoom in={true}>
        <Card 
          elevation={3} 
          sx={{ 
            borderRadius: 3, 
            mb: 2, 
            border: `2px solid ${theme.palette[getStatusColor(scan.status) as 'success' | 'error' | 'primary'].light}`,
            '&:hover': {
              transform: 'translateY(-2px)',
              boxShadow: theme.shadows[8],
              transition: 'all 0.3s ease-in-out'
            }
          }}
        >
          <CardContent sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Avatar 
                  sx={{ 
                    bgcolor: `${getStatusColor(scan.status)}.main`,
                    width: 48,
                    height: 48
                  }}
                >
                  {getStatusIcon(scan.status)}
                </Avatar>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                    Scan {scan.scan_id.slice(0, 8)}...
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {dateInfo.relative} • {dateInfo.time}
                  </Typography>
                </Box>
              </Box>
              
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <Chip
                  label={scan.status.toUpperCase()}
                  color={getStatusColor(scan.status)}
                  size="small"
                  sx={{ fontWeight: 'bold' }}
                />
                <IconButton
                  size="small"
                  onClick={(e) => handleMenuOpen(e, scan.scan_id)}
                >
                  <MoreIcon />
                </IconButton>
              </Box>
            </Box>

            {/* Progress and Status Info */}
            {scan.status === 'running' && (
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">{scan.current_step}</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                    {scan.progress}%
                  </Typography>
                </Box>
                <Box sx={{ 
                  height: 8, 
                  bgcolor: 'grey.200', 
                  borderRadius: 4,
                  overflow: 'hidden'
                }}>
                  <Box
                    sx={{
                      height: '100%',
                      width: `${scan.progress}%`,
                      bgcolor: 'primary.main',
                      transition: 'width 0.3s ease-in-out'
                    }}
                  />
                </Box>
              </Box>
            )}

            {/* Security Score Display */}
            {securityScore && scan.status === 'completed' && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 'bold' }}>
                  Security Assessment
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center', bgcolor: 'primary.light', color: 'white' }}>
                      <Typography variant="h5" sx={{ fontWeight: 'bold' }}>
                        {securityScore.score}
                      </Typography>
                      <Typography variant="caption">Security Score</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h5" sx={{ fontWeight: 'bold', color: 'error.main' }}>
                        {securityScore.total}
                      </Typography>
                      <Typography variant="caption">Total Issues</Typography>
                    </Paper>
                  </Grid>
                </Grid>
                
                {securityScore.total > 0 && (
                  <Box sx={{ display: 'flex', gap: 1, mt: 2, justifyContent: 'center' }}>
                    {securityScore.critical > 0 && (
                      <Chip label={`${securityScore.critical} Critical`} color="error" size="small" />
                    )}
                    {securityScore.high > 0 && (
                      <Chip label={`${securityScore.high} High`} color="warning" size="small" />
                    )}
                    {securityScore.medium > 0 && (
                      <Chip label={`${securityScore.medium} Medium`} color="info" size="small" />
                    )}
                  </Box>
                )}
              </Box>
            )}

            {/* Scan Metadata */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 3 }}>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                {scan.end_time && (
                  <Tooltip title="Scan Duration">
                    <Chip
                      icon={<SpeedIcon />}
                      label={getDuration(scan.start_time, scan.end_time)}
                      variant="outlined"
                      size="small"
                    />
                  </Tooltip>
                )}
                <Tooltip title="Start Date">
                  <Chip
                    icon={<CalendarIcon />}
                    label={dateInfo.date}
                    variant="outlined"
                    size="small"
                  />
                </Tooltip>
              </Box>
              
              {scan.status === 'completed' && (
                <Button
                  variant="contained"
                  startIcon={<ViewIcon />}
                  onClick={() => handleViewReport(scan.scan_id)}
                  size="small"
                  sx={{ borderRadius: 2 }}
                >
                  View Report
                </Button>
              )}
            </Box>

            {/* Error Information */}
            {scan.error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  <strong>Error:</strong> {scan.error}
                </Typography>
              </Alert>
            )}
          </CardContent>
        </Card>
      </Zoom>
    );
  };

  if (loading) {
    return (
      <Container maxWidth="lg">
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minHeight: 400, justifyContent: 'center' }}>
          <CircularProgress size={60} sx={{ mb: 2 }} />
          <Typography variant="h6" color="text.secondary">
            Loading Scan History...
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Fetching your security scan records
          </Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      {/* Header with Statistics */}
      <Paper elevation={3} sx={{ p: 4, mb: 4, borderRadius: 3, background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)', color: 'white' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3, flexDirection: isMobile ? 'column' : 'row', gap: 2 }}>
          <Box>
            <Typography variant={isMobile ? "h4" : "h3"} component="h1" gutterBottom sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 2 }}>
              <HistoryIcon sx={{ fontSize: 'inherit' }} />
              Scan History
            </Typography>
            <Typography variant="h6" sx={{ opacity: 0.9 }}>
              Complete history of security assessments and vulnerability scans
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Refresh History">
              <IconButton
                onClick={fetchScans}
                sx={{ 
                  backgroundColor: 'rgba(255,255,255,0.2)',
                  color: 'white',
                  '&:hover': { backgroundColor: 'rgba(255,255,255,0.3)' }
                }}
              >
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            <Button
              startIcon={<DashboardIcon />}
              onClick={() => navigate('/')}
              variant="outlined"
              sx={{ 
                color: 'white', 
                borderColor: 'white',
                '&:hover': { 
                  backgroundColor: 'rgba(255,255,255,0.1)',
                  borderColor: 'white'
                }
              }}
            >
              Dashboard
            </Button>
          </Box>
        </Box>

        {/* Statistics Dashboard */}
        <Grid container spacing={3}>
          <Grid item xs={6} sm={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <TrendingUpIcon sx={{ fontSize: isMobile ? 30 : 40, mb: 1, opacity: 0.9 }} />
                <Typography variant={isMobile ? "h5" : "h4"} sx={{ fontWeight: 'bold' }}>
                  {stats.total}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Total Scans
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <CheckIcon sx={{ fontSize: isMobile ? 30 : 40, mb: 1, opacity: 0.9 }} />
                <Typography variant={isMobile ? "h5" : "h4"} sx={{ fontWeight: 'bold' }}>
                  {stats.completed}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Completed
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <BugIcon sx={{ fontSize: isMobile ? 30 : 40, mb: 1, opacity: 0.9 }} />
                <Typography variant={isMobile ? "h5" : "h4"} sx={{ fontWeight: 'bold' }}>
                  {stats.totalIssues}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Total Issues
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card elevation={2} sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent sx={{ textAlign: 'center', p: isMobile ? 2 : 3 }}>
                <SpeedIcon sx={{ fontSize: isMobile ? 30 : 40, mb: 1, opacity: 0.9 }} />
                <Typography variant={isMobile ? "h5" : "h4"} sx={{ fontWeight: 'bold' }}>
                  {stats.avgDuration}s
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  Avg Duration
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <Typography variant="h6" gutterBottom>Loading Failed</Typography>
          <Typography variant="body2">{error}</Typography>
        </Alert>
      )}

      {/* Enhanced Filters and Search */}
      <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold', mb: 3 }}>
          Filter & Search Scans
        </Typography>
        
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              placeholder="Search scans..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
            />
          </Grid>
          
          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth>
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                label="Status"
                onChange={(e) => setStatusFilter(e.target.value)}
                sx={{ borderRadius: 2 }}
              >
                <MenuItem value="all">All Status</MenuItem>
                <MenuItem value="completed">Completed</MenuItem>
                <MenuItem value="running">Running</MenuItem>
                <MenuItem value="error">Failed</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth>
              <InputLabel>Date Range</InputLabel>
              <Select
                value={dateFilter}
                label="Date Range"
                onChange={(e) => setDateFilter(e.target.value)}
                sx={{ borderRadius: 2 }}
              >
                <MenuItem value="all">All Time</MenuItem>
                <MenuItem value="today">Today</MenuItem>
                <MenuItem value="week">Last 7 Days</MenuItem>
                <MenuItem value="month">Last Month</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth>
              <InputLabel>Sort By</InputLabel>
              <Select
                value={sortBy}
                label="Sort By"
                onChange={(e) => setSortBy(e.target.value)}
                sx={{ borderRadius: 2 }}
              >
                <MenuItem value="start_time">Date</MenuItem>
                <MenuItem value="duration">Duration</MenuItem>
                <MenuItem value="status">Status</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2}>
            <Button
              fullWidth
              variant="outlined"
              startIcon={<SortIcon />}
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              sx={{ height: '56px', borderRadius: 2 }}
            >
              {sortOrder === 'asc' ? 'Ascending' : 'Descending'}
            </Button>
          </Grid>
        </Grid>
        
        <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            Showing {filteredScans.length} of {scans.length} scans
          </Typography>
          <Chip 
            label={`${filteredScans.length} results`} 
            color="primary" 
            variant="outlined" 
          />
        </Box>
      </Paper>

      {/* Scan Results */}
      {filteredScans.length === 0 ? (
        <Paper elevation={2} sx={{ p: 6, textAlign: 'center', borderRadius: 3 }}>
          <HistoryIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h5" color="text.secondary" gutterBottom sx={{ fontWeight: 'bold' }}>
            {scans.length === 0 ? 'No scans found' : 'No matching scans'}
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: 'auto' }}>
            {scans.length === 0 
              ? 'Start your first security scan from the dashboard to see scan history here.'
              : 'Try adjusting your search criteria or filters to find the scans you\'re looking for.'
            }
          </Typography>
          {scans.length === 0 ? (
            <Button
              variant="contained"
              startIcon={<DashboardIcon />}
              onClick={() => navigate('/')}
              size="large"
              sx={{ borderRadius: 3 }}
            >
              Go to Dashboard
            </Button>
          ) : (
            <Button
              variant="outlined"
              onClick={() => {
                setSearchQuery('');
                setStatusFilter('all');
                setDateFilter('all');
              }}
              size="large"
              sx={{ borderRadius: 3 }}
            >
              Clear Filters
            </Button>
          )}
        </Paper>
      ) : (
        <Fade in={true}>
          <Box>
            {/* Scan Cards */}
            <Grid container spacing={3}>
              {filteredScans
                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                .map((scan) => (
                  <Grid item xs={12} lg={6} key={scan.scan_id}>
                    <ScanCard scan={scan} />
                  </Grid>
                ))}
            </Grid>

            {/* Pagination */}
            {filteredScans.length > rowsPerPage && (
              <Paper elevation={2} sx={{ mt: 3, borderRadius: 2 }}>
                <TablePagination
                  component="div"
                  count={filteredScans.length}
                  page={page}
                  onPageChange={(e, newPage) => setPage(newPage)}
                  rowsPerPage={rowsPerPage}
                  onRowsPerPageChange={(e) => {
                    setRowsPerPage(parseInt(e.target.value, 10));
                    setPage(0);
                  }}
                  rowsPerPageOptions={[5, 10, 25, 50]}
                  sx={{
                    '& .MuiTablePagination-toolbar': {
                      paddingLeft: 3,
                      paddingRight: 3,
                    }
                  }}
                />
              </Paper>
            )}
          </Box>
        </Fade>
      )}

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
      >
        <MenuList>
          <ListItemButton onClick={() => {
            if (selectedScan) handleViewReport(selectedScan);
            handleMenuClose();
          }}>
            <ListItemIcon>
              <ViewIcon />
            </ListItemIcon>
            <ListItemText primary="View Report" />
          </ListItemButton>
          <ListItemButton onClick={() => {
            navigator.clipboard.writeText(selectedScan || '');
            handleMenuClose();
          }}>
            <ListItemIcon>
              <DownloadIcon />
            </ListItemIcon>
            <ListItemText primary="Copy Scan ID" />
          </ListItemButton>
          <Divider />
          <ListItemButton 
            onClick={() => {
              if (selectedScan) handleDeleteScan(selectedScan);
              handleMenuClose();
            }}
            sx={{ color: 'error.main' }}
          >
            <ListItemIcon>
              <DeleteIcon color="error" />
            </ListItemIcon>
            <ListItemText primary="Delete Scan" />
          </ListItemButton>
        </MenuList>
      </Menu>
    </Container>
  );
};

export default ScanHistory; 