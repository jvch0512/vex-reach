const express = require('express');
const { unpackSync: unpack } = require('minipack');

const app = express();

app.post('/upload', (req, res) => {
  const files = unpack(req.body);
  res.json({ count: files.length });
});

module.exports = app;
