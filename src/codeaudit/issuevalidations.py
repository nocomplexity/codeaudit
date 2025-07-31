"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 

Issue validation functions for codeaudit
"""

import ast
import warnings
from collections import defaultdict
from codeaudit.checkmodules import get_imported_modules

def get_full_attr_name(node):
    """Recursively builds full dotted name from Attribute/Name nodes."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def find_constructs(source_code, constructs_to_detect):
    """
    Detects specified constructs (e.g., 'os', 'os.access', 'eval') in the code.
    Handles aliases, from-imports, deep nesting, and avoids double-counting.
    """
    with warnings.catch_warnings():  # Suppression of warnings
        warnings.simplefilter("ignore", category=SyntaxWarning)
        tree = ast.parse(source_code)
    
        results = defaultdict(list)
        seen = set()  # (construct, lineno) pairs already counted

        # step 0: Create a module list - needed for some checks
        imported_modules = get_imported_modules(source_code)
        core_modules = imported_modules['core_modules'] #Only interested in core modules that are imported

        # Step 1: Build alias map
        alias_map = {}
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    alias_map[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module
                for alias in node.names:
                    full_name = f"{module}.{alias.name}"
                    alias_map[alias.asname or alias.name] = full_name

        # Step 2: Walk the AST
        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            construct = None

            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    full = get_full_attr_name(func)
                    prefix = full.split(".")[0]
                    resolved_prefix = alias_map.get(prefix, prefix)
                    full_resolved = resolved_prefix + full[len(prefix) :]                                
                    if full_resolved in constructs_to_detect:
                        construct = full_resolved                
                    elif node.func.attr in ('extractall', 'extract') and 'tarfile' in core_modules:   #note only in combination with tarfile import or alias - see step 1                                      
                        #construct = full_resolved
                        construct = 'tarfile.TarFile'
                elif isinstance(func, ast.Name):
                    resolved = alias_map.get(func.id, func.id)                
                    if resolved in constructs_to_detect:
                        construct = resolved
            
            # Attribute usage: path.exists
            elif isinstance(node, ast.Attribute):
                full = get_full_attr_name(node)
                prefix = full.split(".")[0]
                resolved_prefix = alias_map.get(prefix, prefix)
                full_resolved = resolved_prefix + full[len(prefix) :]
                if full_resolved in constructs_to_detect:
                    construct = full_resolved

            # Name usage: e.g. eval, os
            elif isinstance(node, ast.Name):
                resolved = alias_map.get(node.id, node.id)
                if resolved in constructs_to_detect:
                    construct = resolved

            # ast.Assert node ,to check on assert - assert is the only valid ast.Assert node!
            elif isinstance(node, ast.Assert):
                if "assert" in constructs_to_detect:
                    construct = "assert"

            # ast.ExceptHandler — detect use of bare `pass` inside body
            elif isinstance(node, ast.ExceptHandler):
                if "pass" in constructs_to_detect:
                    for stmt in node.body:
                        if isinstance(stmt, ast.Pass):
                            construct = "pass"                      
            # ast.ExceptHandler — detect use of bare `continue` inside body
                if "continue" in constructs_to_detect:
                    for stmt in node.body:
                        if isinstance(stmt, ast.Continue):
                            construct = "continue"

            # If valid construct and not yet seen at this line
            if construct and lineno and (construct, lineno) not in seen:
                results[construct].append(lineno)
                seen.add((construct, lineno))

    # sort the results by line number
    data = dict(results)
    sorted_results = {k: sorted(v) for k, v in data.items()}
    return dict(sorted_results)


