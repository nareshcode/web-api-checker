import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  IconButton,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Dashboard as DashboardIcon,
  History as HistoryIcon,
  MenuBook as WikiIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';

const Navigation: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <AppBar position="static" sx={{ mb: 3 }}>
      <Toolbar>
        <IconButton
          edge="start"
          color="inherit"
          aria-label="menu"
          sx={{ mr: 2 }}
        >
          <SecurityIcon />
        </IconButton>
        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
          CyberSec Bot - API Security Scanner
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            color="inherit"
            startIcon={<DashboardIcon />}
            onClick={() => navigate('/')}
            variant={location.pathname === '/' ? 'outlined' : 'text'}
            sx={{
              borderColor: location.pathname === '/' ? 'white' : 'transparent',
              color: 'white',
            }}
          >
            Dashboard
          </Button>
          <Button
            color="inherit"
            startIcon={<WikiIcon />}
            onClick={() => navigate('/wiki')}
            variant={location.pathname === '/wiki' ? 'outlined' : 'text'}
            sx={{
              borderColor: location.pathname === '/wiki' ? 'white' : 'transparent',
              color: 'white',
            }}
          >
            Security Wiki
          </Button>
          <Button
            color="inherit"
            startIcon={<HistoryIcon />}
            onClick={() => navigate('/history')}
            variant={location.pathname === '/history' ? 'outlined' : 'text'}
            sx={{
              borderColor: location.pathname === '/history' ? 'white' : 'transparent',
              color: 'white',
            }}
          >
            Scan History
          </Button>
          <Button
            color="inherit"
            onClick={() => navigate('/test')}
            variant={location.pathname === '/test' ? 'outlined' : 'text'}
            sx={{
              borderColor: location.pathname === '/test' ? 'white' : 'transparent',
              color: 'white',
            }}
          >
            🧪 Test
          </Button>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navigation; 