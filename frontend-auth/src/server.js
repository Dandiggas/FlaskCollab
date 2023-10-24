const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// Proxy endpoints
const FRONTEND_TARGET = 'http://localhost:3000';
const BACKEND_TARGET = 'https://localhost:2000';

// Frontend proxy: All non-api requests are redirected to the frontend
const frontendProxy = createProxyMiddleware({
  target: FRONTEND_TARGET,
  changeOrigin: true,
  logLevel: 'debug', // This will log all proxy activity
});

// Backend proxy: All /api requests are redirected to the backend
const backendProxy = createProxyMiddleware({
  target: BACKEND_TARGET,
  changeOrigin: true,
  secure: false, // If you're using self-signed certificates
  pathRewrite: {
    '^/api': '', // remove the /api from the URL path
  },
  logLevel: 'debug',
});

// Apply the proxies
app.use('/api', backendProxy); // This tells the proxy to use the backendProxy for any route that starts with '/api'
app.use('/', frontendProxy);   // This tells the proxy to use the frontendProxy for all other routes

// SSL configuration
const sslOptions = {
  key: fs.readFileSync(path.resolve(__dirname, '../certificate/key.pem'), 'utf8'),
  cert: fs.readFileSync(path.resolve(__dirname, '../certificate/cert.pem'), 'utf8'),
};

// Start server
https.createServer(sslOptions, app).listen(8000, () => {
  console.log('Listening on https://localhost:8000');
});
