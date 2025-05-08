#!/usr/bin/env python3
"""
Script Name: sirens_call.py
Description:
    This script generates Mermaid Graph definitions of the execution flow
    in a specified project. It differentiates between internal project files
    and third-party libraries (e.g., node_modules) and performs a two-pass
    analysis to ensure proper call edges between components.

    Each Commander definition (command chain) is treated as a distinct
    execution entry point.

Author:
    Felix of YGHT, ably assisted by ChatGPT o3-mini-high

Date: 2025-03-26
Version: 0.7.3
License: Affero GPL (AGPL)

Notes:
    Recommended to run in a pipenv. Initialize with:
       pipenv install tree-sitter tree-sitter-javascript

Usage:
    Run this script with:
       pipenv run python sirens_call.py -o <prefix> [--verbose] <target project directory>
    (The -o value is used as a prefix; output files will have a ".mermaid" extension.)
"""

import os
import sys
import re
import argparse
import inspect
import webbrowser
from collections import defaultdict, deque

import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS AND INITIAL SETUP
# -----------------------------------------------------------------------------

# Build Tree-sitter JavaScript language object
JS_LANGUAGE = Language(tsjavascript.language())

# Create a parser instance configured for JavaScript
parser = Parser(JS_LANGUAGE)

# Mermaid styling defaults
MERMAID_THEME = 'default'
MERMAID_LOOK = 'classic'
MERMAID_LAYOUT = 'dagre'
MERMAID_CURVE = 'curve'
MERMAID_NODE_SPACING = 50
MERMAID_RANK_SPACING = 150
MERMAID_ENTRY_POINT_STYLE = 'fill:#f9f,stroke:#333,stroke-width:2px'
MERMAID_EDGE_PRIMARY_STYLE = 'stroke-width:2px,stroke:#333;'
MERMAID_EDGE_SECONDARY_STYLE = 'stroke-dasharray: 5 3,stroke:#999,opacity:0.8;'

# Characters we need to sanitize from Mermaid labels
UNSAFE_CHARS_REMOVE = '"\'[]{}$,<>\\`-\n*+/|^:'
UNSAFE_CHARS_REPLACE_SOURCE = '()'
UNSAFE_CHARS_REPLACE_SINK = '__'
MAX_LABEL_LEN = 50

# Will be set True if --verbose is used
VERBOSE = False

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
node_counter = 0  # Simple incremental ID used for function nodes (internal only)
function_nodes = {}
"""
dict[str, FunctionNode]:
    Keys are node IDs, values are FunctionNode instances.
    e.g. "N0" -> FunctionNode(node_id="N0", ...)
"""

edges = []
"""
list[tuple[str, str, str, int]]:
    List of edges in the form (caller_id, callee_id, label, sequence_index).
    Where 'caller_id' and 'callee_id' are the global node IDs (e.g., 'N0', 'N1')
"""

function_lookup = {}
"""
dict[tuple[str, int, str], FunctionNode]:
    Key is (file_path, line, name) to deduplicate function nodes.
"""

global_dummy_by_file = {}
"""
dict[str, str]:
    Key is file path, value is the node_id of a "dummy" function node for
    calls not contained in a function within that file.
"""

# -----------------------------------------------------------------------------
# DATA STRUCTURES
# -----------------------------------------------------------------------------

class FunctionNode:
    """
    Represents a function in the target codebase.

    Attributes:
        node_id (str): Unique ID for the node (e.g., 'N0', 'N1'), assigned globally.
        name (str): The function's identified name (or "anonymous").
        file_path (str): File path or "external" to indicate a 3rd-party or unknown source.
        line (int or None): The line number where the function is declared (1-based).
        is_entry_point (bool): Flag indicating whether this is a Commander entry point.
        command_title (str or None): Commander command label (if any).
    """
    def __init__(self, node_id, name, file_path, line=None, is_entry_point=False, command_title=None):
        self.node_id = node_id
        self.name = name
        self.file_path = file_path
        self.line = line
        self.is_entry_point = is_entry_point
        self.command_title = command_title

    def label(self) -> str:
        """
        Builds a sanitized label for the Mermaid node display, including
        a tooltip-like notation (file:line). If 'command_title' is set,
        we prefix the function name with "Command:".

        Returns:
            str: A sanitized label for Mermaid usage.
        """
        if self.line:
            tooltip = f"{os.path.basename(self.file_path)}:{self.line}"
        else:
            tooltip = f"{os.path.basename(self.file_path)}"

        # If there's a command title, incorporate it into the function name
        if self.command_title:
            # so the label includes e.g. "Command: doStuff"
            if not self.name.startswith("Command:"):
                self.name = smart_join("Command:", self.name)

        sanitized_name = sanitize_label(self.name)
        sanitized_tooltip = sanitize_label(tooltip)

        return f"{sanitized_name} {sanitized_tooltip}"

# -----------------------------------------------------------------------------
# LOGGING / DEBUG OUTPUT HELPER
# -----------------------------------------------------------------------------

def log_message(msg: str, prefix="Sirens call", debug=False, component=None) -> None:
    """
    Prints a message with a prefix. If debug=True, only prints if VERBOSE is enabled.
    If a 'component' value is provided, it is appended to the prefix string.
    """
    # Capture caller info for more descriptive debug messages
    stack = inspect.stack()
    caller = stack[1]  # The caller's stack frame

    # If it's a debug message and we're not in VERBOSE mode, skip printing
    if debug and not VERBOSE:
        return

    # If debug=True, augment the prefix with info about caller function and line
    if debug:
        prefix = f'DEBUG: {caller.function}():{caller.lineno}'
    if component:
        prefix = prefix + ' | ' + component

    print(f"[{prefix}] {msg}")

# -----------------------------------------------------------------------------
# SANITIZATION / UTILITY FUNCTIONS
# -----------------------------------------------------------------------------

def sanitize_label(text: str) -> str:
    """
    Removes characters in UNSAFE_CHARS from the given text
    so it can be safely included in a Mermaid node label.

    Args:
        text (str): The label text to sanitize.

    Returns:
        str: Sanitized text with unsafe characters removed.
    """
    text_replaced_chars = text.translate(str.maketrans(UNSAFE_CHARS_REPLACE_SOURCE, UNSAFE_CHARS_REPLACE_SINK))
    text_removed_chars = text_replaced_chars.translate(str.maketrans('', '', UNSAFE_CHARS_REMOVE))
    return " ".join(text_removed_chars.strip().split())[:MAX_LABEL_LEN]

def smart_join(*args) -> str:
    """
    Concatenates all non-empty arguments with a space, ignoring None or empty strings.

    Returns:
        str: The joined string.
    """
    return " ".join(str(arg) for arg in args if arg)

# -----------------------------------------------------------------------------
# NODE CREATION AND STORAGE HELPERS
# -----------------------------------------------------------------------------

def get_new_node_id() -> str:
    """
    Generates a new, unique node ID for each FunctionNode created
    in the **global** sense, e.g. "N0", "N1", etc.

    Returns:
        str: A unique node ID (global).
    """
    global node_counter
    node_id = f"N{node_counter}"
    node_counter += 1
    return node_id

def add_function_node(name, file_path, line, is_entry_point=False, command_title=None) -> FunctionNode:
    """
    Creates (or retrieves) a FunctionNode object. Ensures no duplication
    of nodes that have the same (file_path, line, name). This function
    assigns a global unique node ID, stored in `function_nodes`.

    Args:
        name (str): The function name.
        file_path (str): The file where the function is defined.
        line (int): The line number where the function is defined.
        is_entry_point (bool): Whether this function is a CLI entry point.
        command_title (str | None): Optional Commander command text.

    Returns:
        FunctionNode: The existing or newly-created node.
    """
    key = (file_path, line, name)
    comp = f"{file_path}:{line}"

    # If we already have a node with this signature, update it as needed
    if key in function_lookup:
        node = function_lookup[key]
        if is_entry_point:
            node.is_entry_point = True
        if command_title:
            node.command_title = command_title
        log_message(f"Reusing node {node.node_id} for function '{name}'", debug=True, component=comp)
        return node

    # Otherwise create a new node
    node_id = get_new_node_id()
    node = FunctionNode(node_id, name, file_path, line, is_entry_point, command_title)
    function_nodes[node_id] = node
    function_lookup[key] = node
    log_message(f"Added node {node.node_id} for function '{name}'", debug=True, component=comp)
    return node

def create_external_node(name: str) -> FunctionNode:
    """
    Creates a node representing a function call to an external library
    or code outside the current codebase. We use file_path='external' to denote this.

    Args:
        name (str): The external function reference.

    Returns:
        FunctionNode: A node for the external function call.
    """
    node_id = get_new_node_id()
    node = FunctionNode(node_id, name, "external")
    function_nodes[node_id] = node
    log_message(f"Created external node {node.node_id} for '{name}'", debug=True, component="External")
    return node

def add_edge(caller_id, callee_id, label="", sequence_index=0, isReturn=False, is_external=False) -> None:
    """
    Adds a directed edge from caller_id to callee_id with an optional label
    and call sequence index. Caller and callee IDs are always the **global** IDs.

    Args:
        caller_id (str): The caller function's node ID.
        callee_id (str): The callee function's node ID.
        label (str): Optional label for the edge.
        sequence_index (int): Used to track call order from a single caller.
    """
    # Skip self-calls to keep the BFS layering straightforward.
    if caller_id == callee_id:
        return
    clean_label = sanitize_label(label)
    edges.append((caller_id, callee_id, clean_label, sequence_index, isReturn, is_external))
    comp = f"{caller_id} -> {callee_id}"
    log_message(f"Edge added: {comp} with label '{clean_label}'", debug=True, component="Edges")

# -----------------------------------------------------------------------------
# AST PARSING AND TRAVERSAL
# -----------------------------------------------------------------------------

def traverse(node, source_code, file_path, context, record_edges=True) -> None:
    """
    Recursively traverse the AST, collecting function definitions and
    creating edges for function calls.

    Args:
        node (Node): The current Tree-sitter node.
        source_code (bytes): The raw bytes of source code.
        file_path (str): Path to the file being parsed.
        context (dict): Dictionary carrying state like current_function, sequence_counter, etc.
        record_edges (bool): If False, we only gather function definitions (first pass).
                             If True, we track calls and build edges (second pass).
    """
    comp_file = file_path

    # If in the edges pass but we do not have a 'current_function',
    # attach calls to a dummy 'global' node for that file.
    if record_edges and context.get("current_function") is None:
        if file_path in global_dummy_by_file:
            dummy_node_id = global_dummy_by_file[file_path]
            log_message(f"Using existing dummy global node {dummy_node_id}", debug=True, component=comp_file)
        else:
            dummy = add_function_node(f"global:{os.path.basename(file_path)}", file_path, 0)
            dummy_node_id = dummy.node_id
            global_dummy_by_file[file_path] = dummy_node_id
            log_message(f"Created dummy global node {dummy_node_id}", debug=True, component=comp_file)
        context["current_function"] = dummy_node_id

    # Handle function declarations or expressions
    if node.type in ("function_declaration", "function_expression", "method_definition"):
        name = None

        # For 'function_declaration' or 'function_expression'
        if node.type == "function_declaration" or node.type == "function_expression":
            for child in node.children:
                if child.type == "identifier":
                    name = source_code[child.start_byte:child.end_byte].decode('utf8')
                    break

        # For 'method_definition'
        elif node.type == "method_definition":
            for child in node.children:
                if child.type == "property_identifier":
                    name = source_code[child.start_byte:child.end_byte].decode('utf8')
                    break

        if not name:
            name = "anonymous"

        line = node.start_point[0] + 1  # Convert 0-based index to 1-based line number
        current_fn = add_function_node(name, os.path.basename(file_path), line)

        # Create a new context for inside this function
        new_context = context.copy()
        new_context["current_function"] = current_fn.node_id
        new_context["sequence_counter"] = 0

        log_message(f"Traversing function '{name}' defined at line {line}",
                    debug=True, component=f"{file_path}:{line}")

        # Recurse into the function’s child nodes
        for child in node.children:
            traverse(child, source_code, file_path, new_context, record_edges)
        return

    # Handle call expressions
    if node.type == "call_expression":
        if is_commander_call(node, source_code):
            # Commander-specific logic, unchanged
            process_commander_call(node, source_code, file_path, context, record_edges)
        elif record_edges:
            callee_name, arg_list = extract_call_info(node, source_code)
            if callee_name and context.get("current_function"):
                sequence_index = context.get("sequence_counter", 0)
                context["sequence_counter"] = sequence_index + 1

                # We can incorporate the existing loop_label or simply override:
                loop_label = f"#{sequence_index}"

                # If we’re inside a loop, append that info
                if context.get("loop_condition"):
                    loop_label += " " + sanitize_label(f"(loop: {context['loop_condition']})")

                # Build the label: e.g. myFunc(a, 42)
                call_label = f"{callee_name}({', '.join(arg_list)})"
                # Optionally add the numeric #sequence to the label
                full_label = f"{loop_label} {call_label}"

                # Try to match an internal function node with the same name
                target_node = None
                for fn in function_nodes.values():
                    if fn.name == callee_name and fn.file_path != "external":
                        target_node = fn
                        break

                if target_node:
                    add_edge(context["current_function"], target_node.node_id, full_label, sequence_index, isReturn=True)
                else:
                    external_node = create_external_node(callee_name)
                    add_edge(context["current_function"], external_node.node_id, full_label, sequence_index, isReturn=True, is_external=True)

    # Handle loop statements
    if node.type in (
            "for_statement", "while_statement", "do_statement",
            "for_in_statement", "for_of_statement"
    ):
        cond_text = extract_loop_condition(node, source_code)
        new_context = context.copy()
        new_context["loop_condition"] = cond_text
        log_message(f"Processing loop with condition: {cond_text}",
                    debug=True, component=f"{file_path}:{node.start_point[0] + 1}")

        # Recurse inside the loop body with updated context
        for child in node.children:
            traverse(child, source_code, file_path, new_context, record_edges)
        return

    # If none of the above conditions matched, just recurse on children
    for child in node.children:
        traverse(child, source_code, file_path, context, record_edges)

def extract_callee_name(call_node, source_code) -> str | None:
    """
    Returns a string representing the function name being called
    for a call_expression node. It might be a simple identifier
    or a property in a member_expression chain.

    Args:
        call_node (Node): A Tree-sitter call_expression node.
        source_code (bytes): The raw source code.

    Returns:
        str | None: The name of the callee, or None if not found.
    """
    if len(call_node.children) == 0:
        return None
    callee = call_node.children[0]

    # If it’s just an identifier, return it
    if callee.type == "identifier":
        return source_code[callee.start_byte:callee.end_byte].decode('utf8')

    # If it’s a member_expression, find the rightmost property identifier
    if callee.type == "member_expression":
        for child in callee.children[::-1]:
            if child.type in ("property_identifier", "identifier"):
                return source_code[child.start_byte:child.end_byte].decode('utf8')

    return None


def extract_call_info(call_node, source_code) -> tuple[str | None, list[str]]:
    """
    Returns a tuple of (callee_name, [arg1, arg2, ...]) for a call_expression node.

    Args:
        call_node (Node): A Tree-sitter call_expression node.
        source_code (bytes): The raw source code.

    Returns:
        (callee_name, args_list):
            callee_name (str|None): The function identifier or property name being called.
            args_list (list[str]): The string representation of each argument.
    """
    if not call_node.children:
        return (None, [])

    callee_name = None
    arguments = []

    # Identify the callee name – same logic as extract_callee_name:
    callee = call_node.children[0]
    if callee.type == "identifier":
        callee_name = source_code[callee.start_byte:callee.end_byte].decode('utf8')
    elif callee.type == "member_expression":
        # Grab rightmost property identifier
        for child in callee.children[::-1]:
            if child.type in ("property_identifier", "identifier"):
                callee_name = source_code[child.start_byte:child.end_byte].decode('utf8')
                break

    # Next, gather argument text from the second child if it’s "arguments"
    if len(call_node.children) > 1:
        possible_args = call_node.children[1]
        if possible_args.type == "arguments":
            # Typically the node structure is: "(" <arg> "," <arg> "," ... ")"
            real_args = [c for c in possible_args.children if c.type not in ("(", ")", ",")]
            for arg in real_args:
                # Just grab the exact text of the argument from the source code
                arg_text = source_code[arg.start_byte:arg.end_byte].decode('utf8')
                arguments.append(arg_text.strip())

    return (callee_name, arguments)


def extract_loop_condition(loop_node, source_code) -> str:
    """
    Extracts and returns the condition text for a loop statement node
    (for, while, do, for_in, for_of).

    Args:
        loop_node (Node): The Tree-sitter node for the loop.
        source_code (bytes): The raw source code.

    Returns:
        str: The extracted loop condition or "unknown".
    """
    for child in loop_node.children:
        # If we find a parenthesized_expression, that typically holds the loop condition
        if child.type == "parenthesized_expression":
            text = source_code[child.start_byte:child.end_byte].decode('utf8')
            return text.strip("() ")

        # For for-of or for-in loops, we might capture child text
        if child.type not in ("for", "while", "do", "{", ")"):
            text = source_code[child.start_byte:child.end_byte].decode('utf8')
            return text.strip()

    return "unknown"

def is_commander_call(call_node, source_code) -> bool:
    """
    Checks if the AST node is a .command(...).action(...) usage from Commander.

    Args:
        call_node (Node): The call_expression node to analyze.
        source_code (bytes): The raw source code.

    Returns:
        bool: True if it appears to be a Commander call, False otherwise.
    """
    found_command = False
    found_action = False

    def recursive_search(node):
        nonlocal found_command, found_action
        if node.type in ("property_identifier", "identifier"):
            text = source_code[node.start_byte:node.end_byte].decode('utf8')
            if text == "command":
                found_command = True
            elif text == "action":
                found_action = True

        for child in node.children:
            recursive_search(child)

    recursive_search(call_node)
    return found_command and found_action

# -----------------------------------------------------------------------------
# COMMANDER (.command / .action) LOGIC
# -----------------------------------------------------------------------------

def process_commander_call(call_node, source_code, file_path, context, record_edges):
    """
    Handles Commander-based function calls that define a CLI command
    via .command(...).action(...). Extracts command title, description,
    options, and handler function, marking that handler as an entry point.

    Args:
        call_node (Node): The call_expression node for the .command(...).action(...) usage.
        source_code (bytes): The raw source code.
        file_path (str): The file path currently being analyzed.
        context (dict): The current AST traversal context.
        record_edges (bool): True if we are in the second pass (recording edges).
    """
    command_title = None
    command_description = None
    command_options = []
    handler_node = None
    handler_name = None

    call_text = source_code[call_node.start_byte:call_node.end_byte].decode('utf8')

    # Look for .command("someTitle")
    match = re.search(r'\.command\s*\(\s*["\']([^"\']+)["\']', call_text)
    if match:
        command_title = match.group(1)
        log_message(f"Commander command detected: {command_title}",
                    debug=True, component=f"{file_path}:{call_node.start_point[0] + 1}")

    # Look for .description("someDescription")
    desc_match = re.search(r'\.description\s*\(\s*["\']([^"\']+)["\']', call_text)
    if desc_match:
        command_description = desc_match.group(1)
        log_message(f"Commander description detected: {command_description}", debug=True, component=file_path)

    # Look for all .option("someOption")
    for opt_match in re.finditer(r'\.option\s*\(\s*["\']([^"\']+)["\']', call_text):
        flag = opt_match.group(1)
        command_options.append(flag)
        log_message(f"Commander option detected: {flag}", debug=True, component=file_path)

    # Extract the first argument to .action(...)
    if len(call_node.children) >= 2:
        args_node = call_node.children[1]
        if args_node.type == "arguments":
            real_args = [child for child in args_node.children if child.type not in ("(", ")", ",")]
            if real_args:
                handler_node = real_args[0]

                # Unwrap nested parentheses
                unwrap_count = 0
                while handler_node.type == "parenthesized_expression" and handler_node.children:
                    log_message("Unwrapping parenthesized_expression", debug=True, component=file_path)
                    handler_node = handler_node.children[0]
                    unwrap_count += 1

                handler_type = handler_node.type
                handler_line = handler_node.start_point[0] + 1
                log_message(f"Handler node type: {handler_type} at line {handler_line} (unwrapped {unwrap_count}x)",
                            debug=True, component=file_path)

                # If the handler is an identifier, we note its name
                if handler_type == "identifier":
                    handler_name = source_code[handler_node.start_byte:handler_node.end_byte].decode('utf8')

                log_message(
                    f"Commander action handler found: {handler_name or '[inline function]'}",
                    debug=True, component=f"{file_path}:{call_node.start_point[0] + 1}"
                )

    tooltip_data = sanitize_label(command_description) or ""
    if command_options:
        tooltip_data = smart_join(tooltip_data, "Options:", ", ".join(command_options))

    # Mark the corresponding function as an entry point
    if handler_node:
        if handler_node.type in ("function_expression", "arrow_function"):
            # Inline function in .action()
            hname = command_title if command_title else "commander_handler"
            hline = handler_node.start_point[0] + 1
            handler_function_node = add_function_node(
                hname,
                file_path,
                hline,
                is_entry_point=True,
                command_title=command_title
            )
            log_message(
                f"✅ Marked inline commander handler '{hname}' as entry point",
                debug=True,
                component=f"{file_path}:{hline}"
            )

            # Traverse the inline function’s body to record calls
            new_context = context.copy()
            new_context["current_function"] = handler_function_node.node_id
            for sub in handler_node.children:
                traverse(sub, source_code, file_path, new_context, record_edges)

        elif handler_node.type == "identifier":
            # .action() references a named function
            for fn in function_nodes.values():
                if fn.name == handler_name and fn.file_path == file_path:
                    fn.is_entry_point = True
                    fn.command_title = command_title
                    if tooltip_data:
                        fn.command_title = smart_join(command_title, f"{tooltip_data}")
                    log_message(
                        f"✅ Marked existing function '{handler_name}' as entry point",
                        debug=True,
                        component=file_path
                    )
                    break
        else:
            log_message(f"⚠️ Handler type '{handler_node.type}' not handled", component=file_path)
    else:
        log_message("⚠️ Could not resolve a valid .action() handler", component=file_path)

# -----------------------------------------------------------------------------
# FILE TRAVERSAL AND ANALYSIS
# -----------------------------------------------------------------------------

def traverse_directory(start_dir: str, record_edges: bool) -> None:
    """
    Recursively walks the target directory, collecting .js/.mjs files and
    calls analyze_file() on each. Skips node_modules.

    Args:
        start_dir (str): The directory to begin scanning.
        record_edges (bool): Determines whether we are in the first pass (False)
                             or second pass (True).
    """
    files_to_process = []
    for root, dirs, files in os.walk(start_dir):
        # Skip node_modules
        if "node_modules" in root:
            log_message(f"Skipping directory: {root}", debug=True, component="Directory")
            continue

        for file in files:
            if file.endswith((".mjs", ".js")):
                file_path = os.path.join(root, file)
                files_to_process.append(file_path)

    if not files_to_process:
        # If no JS/MJS files found, log and exit
        log_message("!!!ERROR!!! No .mjs/.js files found in target directory.", component="Validation")
        sys.exit(1)

    log_message(f"Found {len(files_to_process)} .mjs/.js files to process", component="Directory")
    for file_path in files_to_process:
        log_message(f"Analyzing file: {file_path}", debug=True, component="File")
        analyze_file(file_path, record_edges)

def analyze_file(file_path: str, record_edges: bool) -> None:
    """
    Opens and parses a single file with Tree-sitter, then runs 'traverse' on
    the syntax tree. If record_edges=False, we only register function nodes.
    If record_edges=True, we build call edges.

    Args:
        file_path (str): Path to the file being analyzed.
        record_edges (bool): True in the second pass, False in the first pass.
    """
    try:
        with open(file_path, "rb") as f:
            source_code = f.read()
    except Exception as e:
        log_message(f"Error reading file {file_path}: {e}", component="File")
        return

    tree = parser.parse(source_code)
    root_node = tree.root_node
    context = {"current_function": None, "loop_condition": None}

    traverse(root_node, source_code, file_path, context, record_edges)

# -----------------------------------------------------------------------------
# PREVIEW IN BROWSER
# -----------------------------------------------------------------------------

def preview_mermaid(mermaid_code: str, mermaid_file_path: str) -> None:
    """
    Creates an HTML file with a Mermaid diagram and attempts to open
    it in the default web browser.

    Args:
        mermaid_code (str): Mermaid code string.
        mermaid_file_path (str): The file path for the generated .mermaid file.
    """
    pattern = r"(?ms)^---\s*\n.*?\n---\s*\n"
    clean_mermaid = re.sub(pattern, "", mermaid_code).lstrip()

    html = generate_mermaid_html(clean_mermaid)
    base_name = os.path.splitext(mermaid_file_path)[0]
    html_path = base_name + ".html"

    try:
        with open(html_path, "w", encoding="utf8") as f:
            f.write(html)
        webbrowser.open(f"file://{os.path.abspath(html_path)}")
    except Exception as e:
        log_message(f"Error writing or opening preview file: {e}", component="Preview", prefix="!!!ERROR!!!")

def generate_mermaid_html(diagram: str) -> str:
    """
    Given a Mermaid diagram definition string, returns an HTML snippet
    that can be opened in a browser to preview the diagram.

    Args:
        diagram (str): The Mermaid diagram definition.

    Returns:
        str: A minimal HTML file containing the Mermaid diagram for preview.
    """
    diagram_escaped = diagram.replace("\\", "\\\\").replace("`", "\\`")

    return f"""<html>
  <head>
    <meta charset="UTF-8">
    <title>Mermaid Diagram Preview</title>
    <script src="mermaid_11.6.0.min.js"></script>
    <style>
      body {{
        padding: 2rem;
        font-family: sans-serif;
      }}
      .mermaid {{
        background: #f9f9f9;
        padding: 1rem;
        border-radius: 8px;
      }}
      .entryPoint {{
        {MERMAID_ENTRY_POINT_STYLE}
      }}
      .edge_primary {{
        {MERMAID_EDGE_PRIMARY_STYLE}
      }}
      .edge_secondary {{
        {MERMAID_EDGE_SECONDARY_STYLE}
      }}
    </style>
  </head>
  <body>
    <h2>Mermaid Diagram Preview</h2>
    <div id="mermaid-target" class="mermaid"></div>

    <script>
      window.addEventListener("DOMContentLoaded", function() {{
        if (typeof mermaid !== 'undefined') {{
          const graphDefinition = `{diagram_escaped}`;
          const container = document.getElementById("mermaid-target");
          container.innerHTML = graphDefinition;

          mermaid.initialize({{
            startOnLoad: false,
            theme: "{MERMAID_THEME}",
            flowchart: {{
              nodeSpacing: {MERMAID_NODE_SPACING},
              rankSpacing: {MERMAID_RANK_SPACING},
              layout: "{MERMAID_LAYOUT}",
              curve: "{MERMAID_CURVE}"
            }},
            look: "{MERMAID_LOOK}",
            layout: "{MERMAID_LAYOUT}"
          }});

          mermaid.init(undefined, container);
        }} else {{
          console.error("Mermaid failed to load.");
        }}
      }});
    </script>
  </body>
</html>
"""

# -----------------------------------------------------------------------------
# BREADTH-FIRST LAYERING
# -----------------------------------------------------------------------------

def get_bfs_layers(entry_node_id: str) -> dict[str, int]:
    """
    Performs a BFS from 'entry_node_id' to compute a layer index for each
    reachable node. Layer 0 = the entry node, layer 1 = direct children, etc.

    Args:
        entry_node_id (str): The node ID from which to start the traversal.

    Returns:
        dict[str, int]: A map of node_id -> BFS layer number.
    """
    queue = deque([(entry_node_id, 0)])
    layers = {}
    while queue:
        node_id, layer = queue.popleft()
        if node_id in layers:
            continue
        layers[node_id] = layer
        # For each edge from node_id, push the callee with layer+1
        for (caller, callee, _, _, _, _) in edges:
            if caller == node_id:
                queue.append((callee, layer + 1))
    return layers

# -----------------------------------------------------------------------------
# MERMAID GRAPH RENDERING
# -----------------------------------------------------------------------------

def build_mermaid_header() -> list[str]:
    """
    Creates the initial lines for the Mermaid file, including
    front matter and config settings.

    Returns:
        list[str]: A list of lines for the Mermaid file header.
    """
    return [
        "---",
        "config:",
        f"  theme: {MERMAID_THEME}",
        "  flowchart:",
        f"    nodeSpacing: {MERMAID_NODE_SPACING}",
        f"    rankSpacing: {MERMAID_RANK_SPACING}",
        f"    layout: {MERMAID_LAYOUT}",
        "    curve: linear",
        f"  look: {MERMAID_LOOK}",
        f"  layout: {MERMAID_LAYOUT}",
        "---",
        "",
        "flowchart TB"
    ]

def reindex_subgraph_nodes(nodes_in_subgraph):
    """
    Assigns new local IDs for the subgraph nodes such that each subgraph
    starts from N0, N1, N2, etc. Returns a dict mapping from old global IDs
    to new local IDs.

    Args:
        nodes_in_subgraph (list[str]): The global node IDs discovered in the subgraph.

    Returns:
        dict[str, str]: A map old_id -> new_id for the subgraph.
    """
    sorted_nodes = sorted(nodes_in_subgraph)  # for deterministic numbering
    mapping = {}
    count = 0
    for old_id in sorted_nodes:
        mapping[old_id] = f"N{count}"
        count += 1
    return mapping

def render_subgraph_nodes_bfs(bfs_map, node_id_map):
    """
    For BFS layering, group nodes by their BFS layer. Then produce a subgraph
    for each layer (BFSLayer0, BFSLayer1, etc.), using local IDs from node_id_map.

    Args:
        bfs_map (dict[str, int]): A map of old global node_id -> BFS layer index.
        node_id_map (dict[str, str]): Mapping of old_id -> new local ID for the subgraph.

    Returns:
        list[str]: Mermaid lines defining subgraphs and nodes.
    """
    lines = []
    # collect by layer
    layer_dict = defaultdict(list)
    for node_id, layer_num in bfs_map.items():
        layer_dict[layer_num].append(node_id)

    for layer_num in sorted(layer_dict.keys()):
        lines.append(f"subgraph Layer{layer_num}")
        #lines.append("  direction TB")  # always top-down inside the subgraph
        for old_node_id in layer_dict[layer_num]:
            node_obj = function_nodes[old_node_id]
            safe_label = sanitize_label(node_obj.label())
            local_id = node_id_map[old_node_id]
            lines.append(f'  {local_id}["{safe_label}"]')
        lines.append("end")

    return lines

def render_subgraph_edges(edge_list, node_id_map) -> list[str]:
    """
    Renders edges for a subgraph using the local IDs from `node_id_map`.
    We'll classify edges as 'primary' if sequence_index == 0, else 'secondary'.

    Args:
        edge_list (list[tuple[str, str, str, int]]): The edges (global IDs).
        node_id_map (dict[str, str]): Mapping old global ID -> new local ID for subgraph.

    Returns:
        list[str]: Mermaid lines for edges (using local IDs), plus style classDefs.
    """
    lines = []
    edges_by_caller = defaultdict(list)

    for caller, callee, label, sequence, isReturn, is_external in edge_list:
        edges_by_caller[caller].append((callee, label, sequence, isReturn, is_external))

    for caller in sorted(edges_by_caller.keys()):
        outgoing = sorted(edges_by_caller[caller], key=lambda e: e[2])
        for callee, label, sequence, isReturn, is_external in outgoing:
            #style = "primary" if sequence == 0 else "secondary"
            local_caller = node_id_map.get(caller)
            local_callee = node_id_map.get(callee)
            local_isReturn = '<' if isReturn else ''
            line_char = '--' if is_external else '=='
            local_label = f"|{label}|" if label else ''
            if not local_caller or not local_callee:
                # skip edges to or from nodes that are not in this subgraph
                continue
            #lines.append(f"{local_caller} {local_isReturn}{line_char}>{local_label} {local_callee}:::edge_{style}")
            lines.append(f"{local_caller} {local_isReturn}{line_char}>{local_label} {local_callee}")

    lines.append("")
    lines.append(f"classDef edge_primary {MERMAID_EDGE_PRIMARY_STYLE}")
    lines.append(f"classDef edge_secondary {MERMAID_EDGE_SECONDARY_STYLE}")
    return lines

# -----------------------------------------------------------------------------
# FULL GRAPH AND SUBGRAPH GENERATION
# -----------------------------------------------------------------------------

def generate_full_graph() -> str:
    """
    Builds a single Mermaid chart showing every node and edge in the analysis,
    ignoring the BFS layering. Useful as a fallback or debugging output.

    Returns:
        str: The generated Mermaid graph definition string.
    """
    # For the full graph, we don't subgraph by BFS layers.
    # We'll just define nodes, then edges, using global IDs.
    lines = build_mermaid_header()

    # Define nodes
    for node_id, node_obj in sorted(function_nodes.items(), key=lambda x: x[0]):
        lines.append(f'{node_id}["{sanitize_label(node_obj.label())}"]')

    # Define edges
    lines.append("")
    edge_lines = []
    for caller, callee, label, sequence in edges:
        style = "primary" if sequence == 0 else "secondary"
        if label:
            edge_lines.append(f"{caller} -->|{label}| {callee}:::edge_{style}")
        else:
            edge_lines.append(f"{caller} --> {callee}:::edge_{style}")
    lines.extend(edge_lines)

    lines.append("")
    lines.append(f"classDef edge_primary {MERMAID_EDGE_PRIMARY_STYLE}")
    lines.append(f"classDef edge_secondary {MERMAID_EDGE_SECONDARY_STYLE}")

    log_message(f"Generated full debug graph with {len(function_nodes)} nodes", debug=True, component="Graph")
    return "\n".join(lines)

def generate_subgraph(entry_node_id: str) -> str:
    """
    Performs a BFS from a single entry node to find all reachable nodes and edges,
    then generates a Mermaid definition for just that subgraph. Nodes are grouped
    by BFS layer, with layer 0 at the top.

    Args:
        entry_node_id (str): The entry node from which to explore (global ID).

    Returns:
        str: A Mermaid graph definition string for the subgraph.
    """
    # BFS to get layers for reachable nodes
    bfs_map = get_bfs_layers(entry_node_id)
    reachable_nodes = set(bfs_map.keys())

    # Gather edges that connect only among reachable nodes
    sub_edges = []
    for (caller, callee, label, seq_index, isReturn, is_external) in edges:
        if caller in reachable_nodes and callee in reachable_nodes:
            sub_edges.append((caller, callee, label, seq_index, isReturn, is_external))

    # Build the header
    lines = build_mermaid_header()

    # Reindex so each subgraph starts at N0
    node_id_map = reindex_subgraph_nodes(list(reachable_nodes))

    # Render BFS-layered subgraphs and edges
    lines += render_subgraph_nodes_bfs(bfs_map, node_id_map)
    lines += render_subgraph_edges(sub_edges, node_id_map)

    # Mark the local entry node as an entryPoint
    local_entry_id = node_id_map[entry_node_id]
    lines.append(f"class {local_entry_id} entryPoint;")
    lines.append(f"classDef entryPoint {MERMAID_ENTRY_POINT_STYLE};")
    lines.append("")

    log_message(
        f"Generated BFS subgraph for entry point {entry_node_id} with {len(reachable_nodes)} nodes (reindexed).",
        debug=True,
        component="Graph"
    )
    return "\n".join(lines)

# -----------------------------------------------------------------------------
# MAIN LOGIC / ARGUMENT PARSER
# -----------------------------------------------------------------------------

def main() -> None:
    """
    The main CLI entry point:
      - Parses arguments
      - Runs a two-pass analysis (definitions first, then edges)
      - Locates Commander-based entry points (or uses debug fallback)
      - Exports one Mermaid file per entry point (and optionally previews them)
    """
    global VERBOSE
    parser_arg = argparse.ArgumentParser(
        description="Analyze .js/.mjs files and generate Mermaid flowcharts of function execution flow."
    )
    parser_arg.add_argument("start_dir", help="Starting directory for project analysis.")
    parser_arg.add_argument("-o", "--output", help="Output prefix for the Mermaid graph(s).", required=True)
    parser_arg.add_argument("--verbose", action="store_true", help="Enable debug output.")
    parser_arg.add_argument("--debug-graph", action="store_true",
                            help="Generate a full graph output even if no entry points are detected.")
    parser_arg.add_argument("--nopreview", action="store_true",
                            help="Disable the preview of Mermaid graph(s) in browser.")
    args = parser_arg.parse_args()

    VERBOSE = args.verbose
    DEBUG_GRAPH = args.debug_graph

    log_message(f"Starting analysis in directory: {args.start_dir}", component="Main")
    log_message("Beginning first pass (function definitions only)...", debug=True, component="Pass 1")
    traverse_directory(args.start_dir, record_edges=False)
    log_message("First pass complete.", debug=True, component="Pass 1")

    log_message("Beginning second pass (processing call expressions)...", debug=True, component="Pass 2")
    traverse_directory(args.start_dir, record_edges=True)
    log_message("Second pass complete.", debug=True, component="Pass 2")

    # Identify Commander-based entry points
    entry_point_ids = [node.node_id for node in function_nodes.values() if node.is_entry_point]
    log_message(f"Total entry points detected: {len(entry_point_ids)}", component="Main")

    # If no entry points and we have --debug-graph, build the full fallback graph
    if not entry_point_ids:
        if DEBUG_GRAPH:
            log_message(
                "No entry points found, but --debug-graph is enabled. Generating full fallback graph.",
                component="Main",
                prefix='!!WARNING!!'
            )
            fallback_graph = generate_full_graph()
            out_file = f"{args.output}_debug_full_graph.mermaid"
            try:
                with open(out_file, "w", encoding="utf8") as f:
                    f.write(fallback_graph)
                log_message(f"Debug fallback Mermaid graph written to {out_file}", component="Output")
            except Exception as e:
                log_message(f"Error writing fallback graph: {e}", component="Output")
        else:
            log_message(
                "No entry points found. Exiting (consider using --debug-graph).",
                component="Main",
                prefix='!!!ERROR!!!'
            )
        return

    # If exactly one entry point, generate a single mermaid file
    if len(entry_point_ids) == 1:
        graph_def = generate_subgraph(entry_point_ids[0])
        out_file = f"{args.output}.mermaid"
        try:
            with open(out_file, "w", encoding="utf8") as f:
                f.write(graph_def)
            if not args.nopreview:
                log_message(f"Previewing Mermaid graph in browser: {out_file}", component="Preview")
                preview_mermaid(graph_def, out_file)

            log_message(f"Mermaid graph definition written to {out_file}", component="Output")
        except Exception as e:
            log_message(f"Error writing output file: {e}", component="Output")

    # If multiple entry points, generate one subgraph file per entry point
    else:
        for eid in entry_point_ids:
            entry_node = function_nodes[eid]
            safe_name = sanitize_label(entry_node.name).replace(" ", "_")
            out_file = f"{args.output}_{safe_name}.mermaid"
            graph_def = generate_subgraph(eid)
            try:
                with open(out_file, "w", encoding="utf8") as f:
                    f.write(graph_def)
                if not args.nopreview:
                    log_message(f"Previewing Mermaid graph in browser: {out_file}", component="Preview")
                    preview_mermaid(graph_def, out_file)

                log_message(f"{entry_node.name} graph definition complete", component="Output")
            except Exception as e:
                log_message(f"Error writing file {out_file}: {e}", component="Output")

    # If --debug-graph was specified, build the full graph too
    if DEBUG_GRAPH:
        log_message("--debug-graph flag enabled. Generating full graph of all nodes and edges.", component="Main")
        fallback_graph = generate_full_graph()
        out_file = f"{args.output}_debug_full_graph.mermaid"
        try:
            with open(out_file, "w", encoding="utf8") as f:
                f.write(fallback_graph)
            log_message(f"Full debug Mermaid graph written to {out_file}", component="Output")
        except Exception as e:
            log_message(f"Error writing fallback debug graph: {e}", component="Output")

    # Summarize outputs
    if entry_point_ids:
        if len(entry_point_ids) == 1:
            written_files = [f"{args.output}.mermaid"]
        else:
            written_files = [
                f"{args.output}_{sanitize_label(function_nodes[eid].name).replace(' ', '_')}.mermaid"
                for eid in entry_point_ids
            ]
        log_message("Output summary:", component="Summary")
        for fname in written_files:
            log_message(f"  ✓ {fname}", component="Summary")


if __name__ == "__main__":
    main()
