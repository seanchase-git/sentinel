# Sentinel Security Review

**Target:** `tests/fixtures/vulnerable_apps/express_idor`  
**Reviewed:** 2026-07-31T14:48:13-0700 · sentinel 0.1.0 · 465.84s  
**Files:** 2 (2 completed)  
**Findings:** 2 · **Suppressed candidates:** 1 · **Rejected inputs:** 0

## Findings

### CRITICAL (2)

#### A03:2021 Injection

#### `server.js:18-20` — owasp-a03-eval-user-input-javascript

**Severity:** critical · **Judge groundedness:** 1.000

```
app.get('/calc', (req, res) => {
  const result = eval(req.query.expr);
  res.send(String(result));
```

The '/calc' route evaluates user input directly using 'eval()', which can execute arbitrary code.

<details><summary>Grounding rule (verbatim from corpus)</summary>

```yaml
id: owasp-a03-eval-user-input-javascript
taxonomy:
  - owasp: A03:2021
  - cwe: CWE-95
title: Code Injection via eval() on User Input
severity: critical
languages:
  - javascript
  - typescript
frameworks: []
description: |
  Passing user-controlled data to eval(), new Function(), setTimeout/setInterval
  with string arguments, or vm.runInContext executes attacker-supplied code with
  the full privileges of the application process. In a Node.js server this is
  remote code execution; in the browser it enables DOM-based attacks and data
  exfiltration.
detection_criteria: |
  Flag any call where user-influenced data reaches a dynamic code sink:
  - eval(req.query.x), eval(userInput), eval(`...${input}...`)
  - new Function(body) where body derives from request data
  - setTimeout(string, ...) or setInterval(string, ...) with non-literal strings
  - vm.runInNewContext / vm.runInThisContext with request-derived source
example_vulnerable: |
  app.get('/calc', (req, res) => {
    res.send(String(eval(req.query.expr)));
  });
example_secure: |
  app.get('/calc', (req, res) => {
    const value = Number.parseFloat(req.query.expr);
    if (Number.isNaN(value)) return res.status(400).send('invalid');
    res.send(String(value));
  });
references:
  - url: https://owasp.org/Top10/A03_2021-Injection/
    title: OWASP Top 10 A03 Injection
  - url: https://cwe.mitre.org/data/definitions/95.html
    title: CWE-95 Eval Injection
```

</details>

#### `server.js:23-28` — owasp-a03-command-injection-javascript-exec

**Severity:** critical · **Judge groundedness:** 1.000

```
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    if (err) return res.status(500).send('failed');
    res.type('text/plain').send(stdout);
  });
```

The '/ping' route constructs a shell command by concatenating user input ('host') directly into the command string passed to 'exec()'.

<details><summary>Grounding rule (verbatim from corpus)</summary>

```yaml
id: owasp-a03-command-injection-javascript-exec
taxonomy:
  - owasp: A03:2021
  - cwe: CWE-78
title: OS Command Injection via child_process.exec
severity: critical
languages:
  - javascript
  - typescript
frameworks: []
description: |
  child_process.exec and execSync run their argument through a shell, so
  concatenating or interpolating user input into the command lets an attacker
  append shell metacharacters (;, |, &&, $()) and run arbitrary commands as
  the Node process user. The vulnerability is the shell parsing the combined
  string, before any program runs.
detection_criteria: |
  Flag shell execution where user input can reach the command string:
  - exec('cmd ' + userInput, ...) or exec(`cmd ${userInput}`, ...)
  - execSync with a concatenated/interpolated command
  - child_process.exec on values from req.query/req.body/req.params
  Safe pattern to contrast: execFile / spawn with an args array and no shell
  (e.g. execFile('ping', ['-c', '1', host])), where user input is a single
  argument element rather than shell syntax.
example_vulnerable: |
  app.get('/ping', (req, res) => {
    exec('ping -c 1 ' + req.query.host, (err, stdout) => res.send(stdout));
  });
example_secure: |
  const { execFile } = require('child_process');
  app.get('/ping', (req, res) => {
    execFile('ping', ['-c', '1', req.query.host], (err, stdout) => res.send(stdout));
  });
references:
  - url: https://owasp.org/Top10/A03_2021-Injection/
    title: OWASP Top 10 A03 Injection
  - url: https://cwe.mitre.org/data/definitions/78.html
    title: CWE-78 OS Command Injection
```

</details>

## Suppressed candidates (audit trail)

Candidates rejected by the deterministic validator or the
groundedness judge. Listed for auditability — these are NOT findings.

- **[judge]** `server.js` rule `owasp-a01-idor-express-javascript` — not grounded (judge score 0.0; reasoning: The candidate explanation assumes the presence of an authenticated user (e.g., 'req.user') to check authorization, but the provided code snippet lacks any authentication middleware or 'req.user' refer)

---

*Every finding above cites a rule from the local corpus (shown verbatim in its
details block) and passed a groundedness check by a local judge model. Models:*

- *deep-review: nvidia/Llama-3_3-Nemotron-Super-49B-v1_5 (NVIDIA, USA)*
- *input-guard: meta-llama/Llama-Guard-3-8B (Meta, USA)*
- *triage: ibm-granite/granite-3.3-2b-instruct (IBM, USA)*
- *judge: ibm-granite/granite-guardian-3.3-8b (IBM, USA)*
- *classify: meta-llama/Llama-3.2-1B-Instruct (Meta, USA)*
- *nomic-embed: nomic-ai/nomic-embed-text-v1.5 (Nomic AI, USA)*
