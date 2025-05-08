# 💜 sirens_call #

**Mermaid Flowchart Generator for JavaScript/Node.js CLI Projects**

Sirens Call is a command-line analysis tool that parses .js and .mjs files in a given project and emits Mermaid.js flowcharts representing the function execution paths—particularly for Commander.js CLI commands. It is ideal for static code reviewers, reverse engineers, and CLI maintainers seeking visual insight into execution logic. When this functionality was needed there appeared to be very little out there that actually did this with modern depenencies, outputting mermaid syntax, and could cope with `commander` style CLI-based entry points.

## 🎞️ Features ##

- 🎯 Identifies distinct execution entry points (e.g., Commander.js .command(...).action(...))
- 🔍 Two-pass AST analysis using Tree-sitter for accurate call graph construction
- 🧠 Differentiates internal code vs third-party (node_modules)
- 🛠️ Generates Mermaid .mermaid files and optional HTML previews
- 🕵️ Built-in support for --verbose debugging and fallback full-graph mode
- 🛠️ CLI interface with sensible defaults, suitable for automation

## 🧱 Installation ##

This tool is best run inside a pipenv environment.

```pipenv install tree-sitter tree-sitter-javascript```

## 🚀 Usage ##

Run sirens_call.py from within the pipenv and point it at a target directory:

```pipenv run python sirens_call.py -o <prefix> [--verbose] [--debug-graph] [--nopreview] <target project directory>```

### Required Arguments ###

- `<target project directory>` Directory containing .js or .mjs files to analyse
- `-o <prefix>`: Output file prefix (each output will be named <prefix>*.mermaid)

### Optional Flags ###

- `--verbose`: Enables diagnostic debug output
- `--debug-graph`: Emits a complete fallback graph even if no entry points are found
- `--nopreview`: Disables automatic HTML preview of generated Mermaid graphs

## 📈 Example ##

```pipenv run python sirens_call.py -o audit_graph ./my-cli-project```

This will:

- Discover Commander-based CLI entry points
- Generate Mermaid flowcharts for each command
- Write them to `audit_graph_<command>.mermaid`
- Preview results in your browser as HTML (unless `--nopreview` is set)

## 🔍 Output ##

Each Mermaid `.mermaid` file contains:

- Subgraphs layered by breadth-first traversal from entry point
- Sanitised function labels with tooltips (e.g. `filename.js:42`)
- External dependencies clearly identified
- Conditional/loop-aware edge annotations

Additionally, when --debug-graph is used, a full merged call graph is written to:

```<prefix>_debug_full_graph.mermaid```

## Future development ##

This project is not in active development, it was made for a project but not needed on a regular basis.  That said, pull requests will be welcomed and if this can be reused in the future it will receive updates too. Rather than let this code rot, it seemed the right thing to do to publish it.

In theory, this script can be updated to cope with any language where the syntax is in tree_sitter.  This isn't tested though so YMMV.  If you have success doing this, please let me know and we can maybe build a version that is a little more immediately flexible / language agnositc.

## Known issues ##

There aren't loads, however, this should not be thought of as a final production-grade tool.  Known issues include:

- Some rendering issues where the call depth is not linear and vertical, i.e. when a function calls another that is also called by another function that is 2 or more layers higher.
- Probably some presentation tidying
- Lots of information could be rendered in the output to show different styles of call
- It currently squashes loops probably a bit more than it should
