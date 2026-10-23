# codeql-lobster

> **Unofficial community project.** Not made, endorsed or supported by GitHub, the CodeQL team or the authors of Lobster. It does not use CodeQL: it reads Lobster source with a small lexer and reports through SARIF.

**Published on the GitHub Marketplace:** [Lobster Analyzer for Code Scanning (unofficial)](https://github.com/marketplace/actions/lobster-analyzer-for-code-scanning-unofficial).

Lobster here is the programming language at [aardappel/lobster](https://github.com/aardappel/lobster).

Static checks for `*.lobster` files that write [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), so results appear under Code scanning next to CodeQL.

CodeQL does not analyze Lobster. This project fills that gap in a limited way.

## Rules

| Rule | Level | What it flags |
| --- | --- | --- |
| `shell-invocation` | warning | `launch_subprocess` given a shell (`sh`, `bash`, `cmd`, `powershell`) plus `-c` or `/c` |
| `string-built-command` | warning | `launch_subprocess` command line built with `+` |
| `read-outside-root` | warning | `read_file` or `write_file` on an absolute path or one containing `..` |
| `literal-secret` | error | a `password`, `secret`, `token` or `api_key` name assigned a non-empty string literal |

There is no Lobster parser. A lexer skips comments and reads strings, so text inside either is never reported. Rules look at call shapes only, so expect misses (aliased functions, calls built at runtime) and some false positives. Text the lexer cannot read becomes a SARIF notification.

## Use it in a repository

Add a job that checks out your repository and runs the action, pinned to a full commit SHA:

```yaml
name: 🔬 Lobster

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  lobster:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: flisk-sh/codeql-lobster@<full commit SHA>
```

Inputs:

- `patterns`: space-separated globs. Default `**/*.lobster`.
- `category`: SARIF category in Code scanning. Default `/language:lobster`.
- `fail-on-findings`: set to `"true"` to fail the step on any result. Default `"false"`, report only.

## Run it locally

```bash
python3 lobster_analyze.py --root path/to/project --output codeql-lobster.sarif
python3 -m unittest tests.test_rules -v
```

Python 3.9 or newer is enough. There are no dependencies.

## Status

Early. The rule set is small, each rule has tests, and the rules come from the standard library docs at [aardappel/lobster](https://github.com/aardappel/lobster). The action has not yet run from a caller on GitHub.

## Releasing

1. Bump `TOOL_VERSION` in `lobster_analyze.py` and merge it to `main`.
2. Tag the merge commit `vX.Y.Z` (matching `TOOL_VERSION`) and push the tag. The release workflow checks the tag, runs the tests and creates the GitHub release with generated notes.
3. Open the created release, choose Edit, and tick "Publish this Action to the GitHub Marketplace". GitHub only allows this from the release page, after accepting the Marketplace terms, so the workflow cannot do it.

## License

MIT. See [LICENSE](LICENSE).
