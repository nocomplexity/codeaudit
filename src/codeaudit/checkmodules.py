"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.


Checking imported Python modules functions for codeaudit
"""

import ast
import sys
import json
import urllib.request

from codeaudit.filehelpfunctions import collect_python_source_files , read_in_source_file 

def get_imported_modules(source_code):
    tree = ast.parse(source_code)
    imported_modules = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # e.g., import os -> os
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            # e.g., from os import path -> os
            module_name = node.module
            if module_name:
                imported_modules.append(module_name)
    imported_modules = list(
        set(imported_modules)
    )  # to make the list with unique values only!
    # distinguish imported modules vs Standard Library
    standard_modules = get_standard_library_modules()
    core_modules = []
    external_modules = []
    for module in imported_modules:
        top_level_module_name = module.split(".")[0]
        if top_level_module_name in standard_modules:
            core_modules.append(module)
        else:
            external_modules.append(module)
    result = {
        "core_modules": sorted(core_modules),
        "imported_modules": sorted(external_modules),
    }
    return result


def get_standard_library_modules():
    """works only Python 3.10+ or higher!"""
    names = []
    if hasattr(sys, "stdlib_module_names"):
        core_modules = sorted(list(sys.stdlib_module_names))
        for module_name in core_modules:
            if not module_name.startswith("_"):
                names.append(module_name)
    return names


def query_osv(package_name, ecosystem="PyPI"):
    """MVP version to check imported module on vulnerabilities on osv db"""
    url = "https://api.osv.dev/v1/query"
    headers = {"Content-Type": "application/json"}
    data = {
        "version": "",  # no version needed for this tool
        "package": {"name": package_name, "ecosystem": ecosystem},
    }

    request = urllib.request.Request(
        url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST"
    )

    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_vuln_info(data):
    results = []
    for vuln in data.get("vulns", []):
        info = {
            "id": vuln.get("id"),
            "details": vuln.get("details"),
            "aliases": vuln.get("aliases", []),
        }
        results.append(info)
    return results


def check_module_on_vuln(module):
    """Retrieves vuln info for external modules using osv-db"""
    result = query_osv(module)
    vulnerability_info = extract_vuln_info(result)
    return vulnerability_info


def get_all_modules(directory_to_scan):
    "Function to get all modules of a package or directory of Python files - never trust requirements.txt or project.toml"    
    files_to_check = collect_python_source_files(directory_to_scan)
    all_int_modules = set()
    all_ext_modules = set()
    for python_file in files_to_check:
        source = read_in_source_file(python_file)
        used_modules = get_imported_modules(source)
        core_modules = used_modules['core_modules']
        external_modules = used_modules['imported_modules']         
        all_int_modules.update(core_modules)
        all_ext_modules.update(external_modules)
    all_modules_discovered = {
        "core_modules": sorted(all_int_modules),
        "imported_modules": sorted(all_ext_modules) }    
    return all_modules_discovered


def get_imported_modules_by_file(python_file_name):
    "Function to get all modules of a package or directory of Python files - never trust requirements.txt or project.toml"
    #total_result=[]        
    source = read_in_source_file(python_file_name)
    used_modules = get_imported_modules(source)
    core_modules = used_modules['core_modules']
    external_modules = used_modules['imported_modules'] 
    # result = { "filename" : python_file ,
    #             "used_modules" : core_modules,
    #             "external_modules": external_modules } 
    #total_result.append(result)
    all_modules_discovered = {
        "core_modules": sorted(core_modules),
        "imported_modules": sorted(external_modules) }    
    return all_modules_discovered
