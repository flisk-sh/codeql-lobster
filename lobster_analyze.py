"""Token-based checks for Lobster files that write SARIF 2.1.0.

There is no Lobster parser here. A small lexer (comments, strings, identifiers,
punctuation) feeds a few call-shape rules. Text the lexer cannot read is reported as
a SARIF notification instead of being skipped silently.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import sys

# --- language config -------------------------------------------------------
DEFAULT_PATTERNS = ["**/*.lobster"]
PATH_FNS = {"read_file", "write_file"}
CHECKED_FNS = set()
COMMAND_FNS = {"launch_subprocess"}
# ---------------------------------------------------------------------------

TOOL_NAME = "codeql-lobster"
TOOL_VERSION = "0.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

ALL_RULES = {
    "unchecked-result": {
        "name": "UncheckedResult",
        "text": "The success flag returned by a file or environment call is discarded.",
        "level": "warning",
    },
    "shell-invocation": {
        "name": "ShellInvocation",
        "text": "A subprocess is started through a shell with a command string.",
        "level": "warning",
    },
    "string-built-command": {
        "name": "StringBuiltCommand",
        "text": "A subprocess command line is built with string concatenation.",
        "level": "warning",
    },
    "literal-secret": {
        "name": "LiteralSecret",
        "text": "A secret-looking name is assigned a string literal.",
        "level": "error",
    },
    "read-outside-root": {
        "name": "ReadOutsideRoot",
        "text": "A file call targets an absolute path or climbs above the project root.",
        "level": "warning",
    },
}


def active_rules():
    rules = {}
    for rule_id, meta in ALL_RULES.items():
        if rule_id == "unchecked-result" and not CHECKED_FNS:
            continue
        if rule_id in ("shell-invocation", "string-built-command") and not COMMAND_FNS:
            continue
        if rule_id == "read-outside-root" and not PATH_FNS:
            continue
        rules[rule_id] = meta
    return rules


SECRET_NAME = re.compile(r"(password|passwd|secret|token|api[_-]?key)", re.IGNORECASE)
SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh"}
SHELL_FLAGS = {"-c", "/c", "-command", "/command"}
OPERATORS = ["::", ":=", "==", "!=", "<=", ">=", "->", "=>", "&&", "||", "<<", ">>", "+=", "-=", "*=", "/="]

IDENT, STRING, CHAR, NUMBER, PUNCT = "ident", "string", "char", "number", "punct"


class Token:
    __slots__ = ("kind", "text", "line", "col")

    def __init__(self, kind, text, line, col):
        self.kind, self.text, self.line, self.col = kind, text, line, col


def lex(source):
    """Return (tokens, problems). problems is a list of (line, message)."""
    tokens, problems = [], []
    i, n, line, line_start = 0, len(source), 1, 0

    def col(pos):
        return pos - line_start + 1

    while i < n:
        c = source[i]
        if c == "\n":
            line += 1
            i += 1
            line_start = i
        elif c in " \t\r":
            i += 1
        elif source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end == -1:
                problems.append((line, "unterminated block comment"))
                i = n
            else:
                chunk = source[i : end + 2]
                newlines = chunk.count("\n")
                if newlines:
                    line += newlines
                    line_start = i + chunk.rfind("\n") + 1
                i = end + 2
        elif source.startswith('"""', i):
            end = source.find('"""', i + 3)
            start_line, start_col = line, col(i)
            if end == -1:
                problems.append((line, "unterminated triple-quoted string"))
                end = n
                body = source[i + 3 :]
            else:
                body = source[i + 3 : end]
            newlines = body.count("\n")
            if newlines:
                line += newlines
                line_start = i + 3 + body.rfind("\n") + 1
            tokens.append(Token(STRING, body, start_line, start_col))
            i = min(end + 3, n)
        elif c in "\"'":
            quote, start, start_line, start_col = c, i, line, col(i)
            i += 1
            closed = False
            while i < n:
                if source[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if source[i] == quote:
                    closed = True
                    i += 1
                    break
                if source[i] == "\n":
                    break
                i += 1
            if not closed:
                problems.append((start_line, "unterminated string"))
            body = source[start + 1 : i - 1] if closed else source[start + 1 : i]
            tokens.append(Token(STRING if quote == '"' else CHAR, body, start_line, start_col))
        elif c.isalpha() or c == "_":
            start = i
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token(IDENT, source[start:i], line, col(start)))
        elif c.isdigit():
            start = i
            while i < n and (source[i].isalnum() or source[i] in "._"):
                i += 1
            tokens.append(Token(NUMBER, source[start:i], line, col(start)))
        else:
            op = next((o for o in OPERATORS if source.startswith(o, i)), c)
            tokens.append(Token(PUNCT, op, line, col(i)))
            i += len(op)
    return tokens, problems


def call_args(tokens, open_index):
    """Tokens between the parenthesis at open_index and its match, and the index after it."""
    depth, j = 0, open_index
    while j < len(tokens):
        t = tokens[j]
        if t.kind == PUNCT and t.text in "([{":
            depth += 1
        elif t.kind == PUNCT and t.text in ")]}":
            depth -= 1
            if depth == 0:
                return tokens[open_index + 1 : j], j + 1
        j += 1
    return tokens[open_index + 1 :], len(tokens)


def is_path_outside_root(value):
    path = value.replace("\\", "/")
    return path.startswith("/") or re.match(r"^[A-Za-z]:/", path) is not None or ".." in path.split("/")


def analyze_source(source, relpath):
    """Return (findings, problems). problems is a list of (line, message)."""
    tokens, problems = lex(source)
    findings = []

    def report(rule, tok, message):
        findings.append({"rule": rule, "message": message, "line": tok.line, "column": tok.col})

    for i, tok in enumerate(tokens):
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None

        # literal-secret: NAME [: type tokens] = "literal"
        if tok.kind == IDENT and SECRET_NAME.search(tok.text) and nxt is not None:
            j = i + 1
            if tokens[j].kind == PUNCT and tokens[j].text == ":":
                while j < len(tokens) and not (tokens[j].kind == PUNCT and tokens[j].text in ("=", ":=", ";")) and j - i < 8:
                    j += 1
            if j + 1 < len(tokens) and tokens[j].kind == PUNCT and tokens[j].text in ("=", ":=") and tokens[j + 1].kind == STRING and tokens[j + 1].text != "":
                report("literal-secret", tokens[j + 1], f"'{tok.text}' is assigned a string literal.")

        if tok.kind != IDENT or nxt is None or not (nxt.kind == PUNCT and nxt.text == "("):
            continue
        name = tok.text
        args, after = call_args(tokens, i + 1)
        first = args[0] if args else None

        if name in PATH_FNS and first is not None and first.kind == STRING and is_path_outside_root(first.text):
            report("read-outside-root", tok, f"{name}(\"{first.text}\") reaches outside the project root.")

        if name in CHECKED_FNS:
            k = i - 1
            while k >= 1 and tokens[k].kind == PUNCT and tokens[k].text in (".", "::") and tokens[k - 1].kind == IDENT:
                k -= 2
            before = tokens[k] if k >= 0 else None
            starts_statement = before is None or (before.kind == PUNCT and before.text in (";", "{", "}"))
            ends_statement = after < len(tokens) and tokens[after].kind == PUNCT and tokens[after].text == ";"
            if starts_statement and ends_statement:
                report("unchecked-result", tok, f"{name}() returns a success flag that is discarded.")

        if name in COMMAND_FNS:
            strings = [a.text.lower() for a in args if a.kind == STRING]
            if any(s in SHELLS for s in strings) and any(s in SHELL_FLAGS for s in strings):
                report("shell-invocation", tok, f"{name}() runs a command string through a shell.")
            if any(a.kind == PUNCT and a.text == "+" for a in args):
                report("string-built-command", tok, f"{name}() builds its command line with '+'.")

    return findings, problems


def discover(root, patterns):
    seen = set()
    for pattern in patterns:
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            if os.path.isfile(path):
                seen.add(os.path.relpath(path, root).replace(os.sep, "/"))
    return sorted(seen)


def fingerprint(rule_id, relpath, message):
    return hashlib.sha256(f"{rule_id}|{relpath}|{message}".encode("utf-8")).hexdigest()


def build_sarif(root, files):
    rules_meta = active_rules()
    rules, rule_index = [], {}
    for rule_id, meta in rules_meta.items():
        rule_index[rule_id] = len(rules)
        rules.append(
            {
                "id": rule_id,
                "name": meta["name"],
                "shortDescription": {"text": meta["text"]},
                "defaultConfiguration": {"level": meta["level"]},
            }
        )

    results, notifications = [], []
    for relpath in files:
        with open(os.path.join(root, relpath), encoding="utf-8", errors="replace") as handle:
            source = handle.read()
        findings, problems = analyze_source(source, relpath)
        for line, message in problems:
            notifications.append(
                {
                    "level": "note",
                    "message": {"text": f"{relpath}: {message}"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": relpath}, "region": {"startLine": line}}}
                    ],
                }
            )
        for item in findings:
            if item["rule"] not in rules_meta:
                continue
            results.append(
                {
                    "ruleId": item["rule"],
                    "ruleIndex": rule_index[item["rule"]],
                    "level": rules_meta[item["rule"]]["level"],
                    "message": {"text": item["message"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": relpath},
                                "region": {"startLine": item["line"], "startColumn": item["column"]},
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "findingHash/v1": fingerprint(item["rule"], relpath, item["message"]),
                    },
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION, "rules": rules}},
                "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
                "results": results,
            }
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check Lobster files and write SARIF.")
    parser.add_argument("--root", default=".", help="project root to scan (default: current directory)")
    parser.add_argument("--pattern", action="append", dest="patterns", help="glob relative to root; repeatable")
    parser.add_argument("--output", default="codeql-lobster.sarif", help="SARIF file to write")
    parser.add_argument("--fail-on-findings", action="store_true", help="exit 1 when any result is reported")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    files = discover(root, args.patterns or DEFAULT_PATTERNS)
    sarif = build_sarif(root, files)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(sarif, handle, indent=2)
        handle.write("\n")

    results = sarif["runs"][0]["results"]
    print(f"Scanned {len(files)} file(s), {len(results)} finding(s). SARIF written to {args.output}.")
    return 1 if args.fail_on_findings and results else 0


if __name__ == "__main__":
    sys.exit(main())
