import axios from 'axios';

const api = axios.create({
    headers: {
        'Content-Type': 'application/json',
    },
});

export const checkHealth = () => api.get('/health');
export const getState = () => api.get('/state');
export const updateConfig = (config) => api.post('/config', config);
export const generateConfig = (params) => api.get('/generate', { params });
export const runPrepare = (params) => api.post('/run/prepare', null, { params });
export const runCheck = () => api.get('/run/check');
export const runStart = () => api.get('/run/start');
export const runStop = () => api.get('/run/stop');
export const getStats = () => api.get('/stats');

export default api;
