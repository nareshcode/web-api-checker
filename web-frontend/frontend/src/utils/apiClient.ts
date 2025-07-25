import axios from 'axios';

// Create axios instance with base configuration
export const apiClient = axios.create({
  baseURL: '/', // Use relative path, setupProxy.js handles routing to backend
  timeout: 30000, // 30 seconds timeout for scans
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for debugging
apiClient.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => {
    console.log(`API Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('API Response Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// API helper functions
export const scanAPI = {
  // Start a new scan
  startScan: (target: string, severity: string = 'all') =>
    apiClient.post('/api/scan/start', { target, severity }),

  // Get scan status
  getScanStatus: (scanId: string) =>
    apiClient.get(`/api/scan/${scanId}`),

  // Get scan report
  getReport: (scanId: string) =>
    apiClient.get(`/api/report/${scanId}`),

  // List all scans
  listScans: () =>
    apiClient.get('/api/scans'),

  // Health check
  healthCheck: () =>
    apiClient.get('/api/health'),

  // Generate AI recommendations
  generateRecommendations: (metrics: any) =>
    apiClient.post('/api/recommendations', { metrics }),
};

export default apiClient; 