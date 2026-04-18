import axios from 'axios';
import useAuthStore from '../store/authStore';

const client = axios.create({
  baseURL: 'http://localhost:5000/api',
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor: attach token
client.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().accessToken;
    if (token && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: handle token refresh
client.interceptors.response.use(
  (response) => {
    // Standardize our success responses if needed, but interceptors operate on raw axios res.
    return response.data; // assume we want the unwrapped data, but wait, typical axis usage returns the response object.
    // the user asked for consistent { success, data, error } backend.
  },
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const { refreshToken, logout, setTokens } = useAuthStore.getState();
      
      if (!refreshToken) {
        logout();
        return Promise.reject(error);
      }
      
      try {
        const res = await axios.post('http://localhost:5000/api/auth/refresh', {}, {
          headers: { Authorization: `Bearer ${refreshToken}` }
        });
        const newToken = res.data.data.access_token;
        setTokens(newToken, refreshToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        // Re-execute original request
        const retryRes = await axios(originalRequest);
        return retryRes.data;
      } catch (err) {
        logout();
        return Promise.reject(err);
      }
    }
    return Promise.reject(error);
  }
);

// Convenience wrapper so callers can use client.delete(url)
const wrappedClient = {
  get:    (url, config) => client.get(url, config),
  post:   (url, data, config) => client.post(url, data, config),
  put:    (url, data, config) => client.put(url, data, config),
  patch:  (url, data, config) => client.patch(url, data, config),
  delete: (url, config) => client.delete(url, config),
};

export default wrappedClient;


// ━━━ Blockchain ━━━
export const getBlockchainStats = () => wrappedClient.get('/blockchain/stats');
export const getBlocks = (p) => wrappedClient.get('/blockchain/blocks', { params: p });
export const validateChain = () => wrappedClient.get('/blockchain/validate');
export const getTransactions = (p) => wrappedClient.get('/blockchain/transactions', { params: p });
export const mineBlock = () => wrappedClient.post('/blockchain/mine');
export const listBCCertificates = () => wrappedClient.get('/blockchain/certificates');
export const verifyBCCertificate = (h) => wrappedClient.get('/blockchain/certificates/verify/' + h);
export const issueBCCertificate = (d) => wrappedClient.post('/blockchain/certificates/issue', d);
export const revokeBCCertificate = (d) => wrappedClient.post('/blockchain/certificates/revoke', d);
export const getSmartContracts = () => wrappedClient.get('/blockchain/contracts');
export const executeContract = (id, d) => wrappedClient.post('/blockchain/contracts/' + id + '/execute', d);
export const getThreatIntel = (p) => wrappedClient.get('/blockchain/threat-intel', { params: p });
export const shareThreatIntel = (d) => wrappedClient.post('/blockchain/threat-intel/share', d);

// ━━━ Banking & Compliance ━━━
export const getBankingTemplates = (p) => wrappedClient.get('/banking/templates', { params: p });
export const createAssetFromTemplate = (id, d) => wrappedClient.post('/banking/templates/' + id + '/create-asset', d);
export const getComplianceFrameworks = () => wrappedClient.get('/banking/compliance/frameworks');
export const checkCompliance = (d) => wrappedClient.post('/banking/compliance/check', d);

// ━━━ Advanced Scanners ━━━
export const scanHTTPHeaders = (d) => wrappedClient.post('/banking/scan/headers', d);
export const scanDNSSecurity = (d) => wrappedClient.post('/banking/scan/dns', d);
export const scanAPISecurity = (d) => wrappedClient.post('/banking/scan/api', d);
