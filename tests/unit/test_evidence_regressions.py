"""Regressions found by adversarial review of the C#/.NET support work.

Every case here is a defect that shipped in the C# diff and silently changed
behaviour for a language that already worked. They are unit tests on purpose:
each one runs with no models, no gateway and no database, so the deterministic
applicability gate is checked by something that cannot be flaky.
"""

from __future__ import annotations

from sentinel.graph.evidence import (
    _CSHARP_INJECTION_SINK_RE,
    _INJECTION_SINK_RE,
    _block_comment_open_at,
    _first_call_argument,
    _mask_non_code,
)
from sentinel.graph.nodes import detect_framework
from sentinel.ingest.chunker import chunk_file
from sentinel.ingest.walker import _is_dotnet_build_output


class TestSinkVocabularyIsLanguageScoped:
    """Generic .NET verbs must not certify ordinary Python/JS calls as sinks."""

    def test_python_file_write_is_not_a_query_operation(self):
        line = '    f.write(user_input + "\\n")'
        assert _first_call_argument(line, False, "python") == ""

    def test_python_int_parse_is_not_a_query_operation(self):
        line = '    value = int.Parse(user_id + "0")'
        assert _first_call_argument(line, False, "python") == ""

    def test_js_console_log_is_not_a_query_operation(self):
        line = '  console.log("user " + name);'
        assert _first_call_argument(line, False, "javascript") == ""

    def test_shared_verbs_still_match_everywhere(self):
        line = "    cur.execute(sql)"
        assert _INJECTION_SINK_RE.search(line) is not None
        assert _first_call_argument(line, False, "python") == "sql"

    def test_csharp_keeps_its_dotnet_vocabulary(self):
        line = '        var cmd = new SqlCommand("SELECT * FROM t WHERE u=" + user, conn);'
        assert _CSHARP_INJECTION_SINK_RE.search(line) is not None
        assert _first_call_argument(line, False, "csharp") != ""


class TestFlaskSSTIStillPasses:
    """CWE-94 was wired to the injection predicate; its sink must be known."""

    def test_render_template_string_is_a_sink(self):
        line = "    return render_template_string(\"<h1>Hi \" + request.args['name'] + \"</h1>\")"
        arg = _first_call_argument(line, False, "python")
        assert arg != ""
        assert "request.args" in arg


class TestMaskerIsLanguageAware:
    def test_js_private_field_is_not_a_comment(self):
        line = "    const rows = await this.#pool.query(`SELECT * FROM u WHERE n='${name}'`);"
        masked, _ = _mask_non_code(line, False, "javascript")
        assert "#pool" in masked
        assert _first_call_argument(line, False, "javascript") != ""

    def test_python_hash_is_still_a_comment(self):
        line = "    x = 1  # cur.execute(evil)"
        masked, _ = _mask_non_code(line, False, "python")
        assert "execute" not in masked

    def test_python_has_no_block_comments(self):
        """A `/*` inside a docstring must not latch comment mode for the file."""
        lines = [
            '"""Query templates live under sql/*.tpl."""',
            "import sqlite3",
            "",
            "def get(cur, name):",
            "    cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")",
        ]
        assert _block_comment_open_at(lines, 5, "python") is False
        arg = _first_call_argument(lines[4], False, "python")
        assert "name" in arg

    def test_python_floor_division_is_not_a_comment(self):
        line = "    half = total // 2; cur.execute(sql)"
        masked, _ = _mask_non_code(line, False, "python")
        assert "execute" in masked

    def test_js_block_comment_still_masks(self):
        line = "  /* db.query(evil) */ const x = 1;"
        masked, _ = _mask_non_code(line, False, "javascript")
        assert "query" not in masked

    def test_unknown_grammar_masks_quotes_only(self):
        line = "    cur.execute(sql)  # not a comment when the grammar is unknown"
        masked, _ = _mask_non_code(line, False, None)
        assert "execute" in masked


class TestFrameworkDetection:
    def test_python_inject_decorator_is_not_aspnetcore(self):
        content = (
            "from fastapi import FastAPI\n"
            "from dependency_injector.wiring import inject\n"
            "\n"
            "@inject\n"
            "def handler():\n"
            "    ...\n"
        )
        assert detect_framework(content, "app/api.py") == "fastapi"

    def test_razor_directive_still_detects_aspnetcore(self):
        content = "@page \"/users\"\n@inject IJSRuntime JS\n<h1>Users</h1>\n"
        assert detect_framework(content, "Pages/Users.razor") == "aspnetcore"

    def test_controller_source_still_detects_aspnetcore(self):
        content = (
            "using Microsoft.AspNetCore.Mvc;\n"
            "public class UsersController : ControllerBase { }\n"
        )
        assert detect_framework(content, "Controllers/UsersController.cs") == "aspnetcore"

    def test_flask_still_wins_for_python(self):
        content = "from flask import Flask\n\n@app.route('/')\ndef index():\n    ...\n"
        assert detect_framework(content, "app.py") == "flask"

    def test_csharp_file_mentioning_react_in_a_comment_is_not_react(self):
        """Ordering cannot fix this; the patterns run over comments too."""
        content = (
            "using Microsoft.AspNetCore.Mvc;\n"
            "// ported from the SPA: import React from \"react\"\n"
            "public class HomeController : ControllerBase { }\n"
        )
        assert detect_framework(content, "Controllers/HomeController.cs") == "aspnetcore"

    def test_python_file_mentioning_express_in_a_comment_is_not_express(self):
        content = (
            "from flask import Flask\n"
            "# replaces the old node service: require('express')\n"
        )
        assert detect_framework(content, "app.py") == "flask"

    def test_unknown_extension_still_tries_every_pattern(self):
        content = "from flask import Flask\n"
        assert detect_framework(content, "script.unknown") == "flask"
        assert detect_framework(content, None) == "flask"


class TestChunkerDoesNotFragment:
    def test_single_line_top_level_statements_do_not_each_become_a_chunk(self):
        source = "\n\n".join(f"const v{i} = require('mod{i}');" for i in range(12))
        chunks = chunk_file(source, "javascript")
        assert len(chunks) <= 3

    def test_real_functions_still_chunk_separately(self):
        source = (
            "function a() {\n  return 1;\n}\n\n"
            "function b() {\n  return 2;\n}\n"
        )
        chunks = chunk_file(source, "javascript")
        assert len(chunks) >= 2


class TestDotnetBuildOutputScoping:
    def test_node_bin_entrypoint_is_reviewed(self, tmp_path):
        (tmp_path / "bin").mkdir()
        cli = tmp_path / "bin" / "cli.js"
        cli.write_text("#!/usr/bin/env node\n")
        (tmp_path / "package.json").write_text("{}")
        assert _is_dotnet_build_output(cli, tmp_path) is False

    def test_dotnet_build_output_is_skipped(self, tmp_path):
        (tmp_path / "Api.csproj").write_text("<Project />")
        out = tmp_path / "bin" / "Debug" / "net8.0"
        out.mkdir(parents=True)
        dll_src = out / "Generated.cs"
        dll_src.write_text("// generated\n")
        assert _is_dotnet_build_output(dll_src, tmp_path) is True

    def test_answer_is_not_cached_across_walks(self, tmp_path):
        """The answer is a fact about mutable directory contents.

        A process-wide cache would review generated output, or drop a real
        bin/cli.js, whenever a tree changed under a path already seen.
        """
        (tmp_path / "bin").mkdir()
        entry = tmp_path / "bin" / "cli.js"
        entry.write_text("const a = 1;")
        assert _is_dotnet_build_output(entry, tmp_path) is False

        (tmp_path / "Api.csproj").write_text("<Project />")
        assert _is_dotnet_build_output(entry, tmp_path) is True

    def test_memo_is_used_within_one_walk(self, tmp_path):
        (tmp_path / "Api.csproj").write_text("<Project />")
        (tmp_path / "bin").mkdir()
        first = tmp_path / "bin" / "A.cs"
        first.write_text("class A {}")
        memo: dict = {}
        assert _is_dotnet_build_output(first, tmp_path, memo) is True
        assert memo == {tmp_path: True}
