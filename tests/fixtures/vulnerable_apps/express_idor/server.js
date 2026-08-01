// Deliberately vulnerable Express app for Sentinel integration tests.
// DO NOT deploy. Vulnerabilities are intentional test fixtures.

const express = require('express');
const { exec } = require('child_process');
const db = require('./db');

const app = express();
app.use(express.json());

// Unauthenticated direct object access: any caller can read any order.
app.get('/api/orders/:id', async (req, res) => {
  const order = await db.orders.findByPk(req.params.id);
  if (!order) return res.sendStatus(404);
  res.json(order);
});

app.get('/calc', (req, res) => {
  const result = eval(req.query.expr);
  res.send(String(result));
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    if (err) return res.status(500).send('failed');
    res.type('text/plain').send(stdout);
  });
});

app.listen(3000, '127.0.0.1', () => {
  console.log('demo server on :3000');
});
