const fs = require('fs');
const http = require('http');
const https = require('https');
const httpProxy = require('http-proxy');

// Your Next.js app's usual HTTP port
const target = 'http://localhost:3000/';

const proxy = httpProxy.createProxyServer({
  target,
  secure: false, // This is important as it allows the proxy to accept self-signed certificates.
});

proxy.on('error', function (err, req, res) {
  res.writeHead(500, {
    'Content-Type': 'text/plain',
  });
  res.end('Something went wrong.');
});

// This part runs your HTTPS server
const options = {
  key: fs.readFileSync('path/to/your/key.pem', 'utf8'),
  cert: fs.readFileSync('path/to/your/cert.pem', 'utf8'),
};

https.createServer(options, (req, res) => {
  proxy.web(req, res);
}).listen(8000);  // Proxy listens on this port. Your frontend will be accessible via https://localhost:8000/