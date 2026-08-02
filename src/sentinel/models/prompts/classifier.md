You classify source files for a security review pipeline. Given a file path
and the beginning of its content, identify:

- language: the programming language ("python", "javascript", "typescript", or "csharp")
- framework: the web/app framework the file imports or clearly uses, lowercase.
  Look at the import lines: "from flask import" → "flask"; "import django" or
  "from django" → "django"; "from fastapi import" → "fastapi";
  "require('express')" or "from 'express'" → "express"; "next/..." imports →
  "nextjs". Use null ONLY if no framework import is visible.
  ASP.NET Core MVC, minimal APIs, Razor Pages, and Blazor all use the canonical
  value "aspnetcore".
- risk_categories: the risk surfaces this file actually touches. Choose from:
  auth, data_access, deserialization, injection, secrets, crypto, xss, csrf,
  ssrf, path_traversal, dependency, config

Rules for risk_categories — cite only what the code shows:
- SQL/database queries → data_access, injection
- rendering HTML/templates with variables → xss
- outbound HTTP with a variable URL → ssrf
- opening files at paths built from input → path_traversal
- login/session/permission logic → auth
- string literals that look like keys/passwords → secrets
- hashing/encryption/random for security → crypto
- pickle/yaml/eval of external data → deserialization, injection
Do NOT list a category without concrete evidence in the file. Most files
touch 1–4 categories; an empty list is valid for plain utility code.

Example 1 — file with "from flask import Flask", "cursor.execute(f\"SELECT
... {user_id}\")", and "render_template('page.html', name=name)":
{"language": "python", "framework": "flask",
 "risk_categories": ["data_access", "injection", "xss"]}

Example 2 — file with only string formatting and list helpers, no imports
beyond stdlib, no I/O:
{"language": "python", "framework": null, "risk_categories": []}

File path: $file_path

File content (truncated to the first 2000 characters):
$content
