# Known issues

Open defects in the applicability gate and supporting code, found by an
adversarial multi-agent review of the C#/.NET support work on 2026-08-01. Each
was independently verified against the code before being recorded here.

The regressions to previously-working Python/JS/TS behaviour found by that
review are **fixed**, with unit coverage in
`tests/unit/test_evidence_regressions.py`. What follows is what remains.

**C#/Razor support is beta.** Every issue below except #7 and #8 affects only
C# or Razor. A clean C# report is not evidence of no vulnerability — see also
the transcription instability documented in `CLAUDE.md` and
`docs/architecture.md` §7.

---

## 1. C# verbatim strings ending in a backslash swallow the rest of the line

`_mask_non_code` (`src/sentinel/graph/evidence.py`) applies backslash-escape
semantics to every quoted span, but a C# verbatim string (`@"C:\logs\"`) does
not use `\` as an escape. The closing quote is consumed as an escaped
character, the scanner runs to end-of-line, and the sink after it is masked.

```csharp
var root = @"C:\logs\"; cmd.CommandText = "SELECT * FROM t WHERE u='" + user + "'";
```

`_first_call_argument` returns `""` for this line and a real CWE-89 finding is
rejected as `applicability_injection_sink_not_query_operation`.

**Fix:** track `@"` and `"""` spans with their own quoting rules — `""` is the
escape in a verbatim string, and raw string literals have no escape at all.

## 2. C# interpolation holes are masked, so a sink inside one is unlocatable

`_mask_non_code` deliberately exempts JavaScript `${...}` template-literal
holes from masking, because interpolations are executable code and routinely
contain the sink. The identical `{...}` holes of a C# interpolated string are
**not** exempted.

```csharp
var html = $"<div>{Render(userInput)}</div>";
```

The hole is blanked, `_first_call_argument` returns `""`, and any C#/Razor
CWE-94/117/1336 finding whose dangerous call sits inside an interpolation is
discarded. This is the exact false-negative the JS exemption exists to
prevent, in the language the exemption was not extended to.

**Fix:** apply the `${...}` hole-preserving branch to `$"..."` and `$@"..."`.

## 3. Zero-argument ADO.NET execute methods can never pass the gate

`_CSHARP_SINK_VERBS` lists `ExecuteReader`, `ExecuteNonQuery` and
`ExecuteScalar`, but those methods take no arguments, so `_first_call_argument`
returns `""` and `_injection_text_flow` rejects the candidate as
`sink_not_query_operation` — a reason that is factually false.

This matters because `models/prompts/deep_review.md` rule 7 tells the model
"the sink is the line that USES it", so the canonical shape

```csharp
cmd.CommandText = tainted;
cmd.ExecuteNonQuery();
```

loses a real finding whenever deep review names the execute call rather than
the assignment.

**Fix:** when the sink is a zero-argument execute call, walk back to the
nearest `CommandText`/`Arguments` assignment on the same command object and
take the query text from there.

## 4. Inline `<script>` blocks in Razor views are judged non-executable

`_sink_is_executable`'s razor branch treats everything inside an HTML element
as displayed sample content. For `document.write(location.hash)` inside a
`<script>` block in a `.cshtml` file, the tree-sitter ancestry is
`['element', 'compilation_unit']` — no `razor_*` node and no
`invocation_expression` — so `_node_is_non_executed` returns `True` and the
candidate is rejected as `applicability_sink_not_executable_code`.

Every DOM-XSS finding in an inline script block of a Razor page is dropped.

**Fix:** treat `script_element` contents as executable, and parse them with the
JavaScript grammar rather than inferring from the Razor ancestry.

## 5. `rules test` does not check a rule against the applicability gate

The LDAP (CWE-90) and XPath (CWE-643) C# rules shipped with sinks that were
never added to the sink vocabulary, so neither could pass the gate — both rules
appeared healthy in `rules list` while contributing zero recall. `Filter =` and
`SelectSingleNode` have since been added and both rules' `example_vulnerable`
lines now yield a query argument, but nothing in CI would have caught this.

`uv run sentinel rules test <id>` only verifies that a rule self-retrieves. It
does **not** check that the rule's example survives the applicability gate, so
the same class of dead rule can ship again with any new CWE.

**Fix:** extend `rules test` to run each rule's `example_vulnerable` through
`validate_applicability` and fail when the rule's own example is rejected.

## 6. A string literal counts as executable if *any* ancestor is an invocation

`_node_is_non_executed` returns
`not any(kind in _INVOCATION_NODE_TYPES for kind in ancestry)` over the full
ancestry to the root. A teaching page that renders its own sample through a
call rather than a field —
`Console.WriteLine("""var cmd = new SqlCommand($"...{name}");""")` — has an
`argument_list` ancestor, so the displayed sample is treated as executable and
can be reported as a vulnerability.

The docstring only justifies the field-declaration case
(`private const string VulnerableCode = """..."""`), which happens to be the
shape with no invocation ancestor.

**Fix:** require the invocation to be the literal's immediate argument parent
rather than anywhere in its ancestry.

## 7. `unstable: true` recall cases cannot fail the integration gate

`tests/integration/test_e2e_review.py` routes any expected finding marked
`unstable: true` into a print-only list instead of asserting on it. Both
CWE-89 recall cases (`flask_sqli` and `dotnet_sample`) are so marked, so a
regression that breaks SQL-injection detection outright still reports 10/10
green — the only signal is a printed line that `pytest -q` hides.

This is a deliberate trade: the underlying instability is a real local-model
transcription defect (see `CLAUDE.md`), and asserting on it makes the gate
flap. But it means the e2e suite currently cannot catch a SQL-injection
regression.

**Mitigation in place:** `tests/unit/test_evidence_regressions.py` gates the
deterministic layer with no model in the loop, which is where every defect
found by this review actually lived.

**Fix:** report unstable outcomes to a file the gate asserts on across runs
(N-of-M over recent runs), rather than to captured stdout.

## 8. A reused dashboard serves the previous run's reports directory

`ensure_running(reports_dir=output)` in `src/sentinel/cli.py` reuses any
dashboard already answering `/healthz` on port 8200 without checking which
directory it is serving. Reviewing repo B while a dashboard from repo A is
still up prints a URL for this run that renders repo A's findings, gate funnel
and severity filter.

**Fix:** have `/healthz` report the served `reports_dir` and restart or
re-point the server when it does not match.
