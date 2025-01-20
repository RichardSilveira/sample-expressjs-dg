require('dotenv').config();
const express = require('express');
const { IpFilter, IpDeniedError } = require('express-ipfilter');

const app = express();
const port = process.env.PORT || 3000;

// Enable trust proxy if behind a proxy/load balancer
app.set('trust proxy', true);

// List of allowed IPs
require('dotenv').config();

const allowedIps = process.env.ALLOWED_IPS.split(',');

// Custom detectIp function for better IP detection
const detectIp = (req) => {
  // Use x-forwarded-for header if present, otherwise fall back to remoteAddress
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0].trim() : req.connection.remoteAddress;
};

// Middleware to log the detected client IP
app.use((req, res, next) => {
  const clientIp = detectIp(req);
  console.log('Detected IP:', clientIp, 'Forwarded:', req.headers['x-forwarded-for']);
  next();
});

// Middleware to allow traffic only from allowed IPs with custom detectIp
app.use(IpFilter(allowedIps, { mode: 'allow', detectIp }));

// Handle errors for blocked IPs
app.use((err, req, res, next) => {
  if (err instanceof IpDeniedError) {
    const clientIp = detectIp(req);
    console.error('Blocked IP:', clientIp);
    res.status(403).send('Access Denied');
  } else {
    next(err);
  }
});

// Define a simple test endpoint
app.get('/', (req, res) => res.send('Hello World!'));

// Start the server
app.listen(port, () =>
  console.log(`sample-expressjs app listening on port ${port}!`)
);
