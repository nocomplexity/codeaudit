"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


Public API functions for Python Code Audit aka codeaudit on pypi.org
"""

from codeaudit import __version__
from codeaudit.filehelpfunctions import get_filename_from_path , collect_python_source_files , is_ast_parsable 
from codeaudit.security_checks import perform_validations , ast_security_checks
from codeaudit.totals import overview_per_file , get_statistics , overview_count , total_modules
from codeaudit.checkmodules import get_all_modules , get_imported_modules_by_file , get_standard_library_modules , check_module_vulnerability
from codeaudit.pypi_package_scan import get_pypi_download_info , get_package_source

from pathlib import Path
import json
import datetime 
import pandas as pd
import platform
from collections import Counter

import altair as alt

def version():
    """Returns the version of Python Code Audit"""
    ca_version = __version__
    return {"name" : "Python_Code_Audit",
             "version" : ca_version}

def filescan(input_path):
    """
    Scan a Python source file, a local directory, or a **PyPI package** from PyPI.org for
    security weaknesses and return the results as a JSON-serializable
    dictionary.

    This API function works on:

    - **Local directory**: Recursively scans all supported Python files in the
      directory.
    - **Single Python file**: Scans the file if it exists and can be parsed
      into an AST.
    - **PyPI package** on PyPI.org: Downloads the
      source distribution from PyPI, scans it, and cleans up temporary files.

    The returned output always includes Python Code Audit version information and a
    generation timestamp. For consistency, single-file scans are normalized
    to match the structure of directory/package scans.

    **Note:**
    The filescan command does NOT include all directories. This is done on purpose!
    The following directories are skipped by default:

    - `/docs`
    - `/docker`
    - `/dist`
    - `/tests`
    - all directories that start with . (dot) or _ (underscore) 
     
    But you can easily change this if needed!

    Args:
        input_path (str): One of the following:
            - Path to a local directory containing Python code.
            - Path to a single ``.py`` file.
            - Name of a package available on PyPI.

    Returns:
        dict: A JSON-serializable dictionary containing scan results and
        metadata. The structure varies slightly depending on the scan type,
        but always includes:
            - Version information from ``version()``.
            - ``generated_on`` timestamp (``YYYY-MM-DD HH:MM``).
            - Package or file-level security findings.

        If the input cannot be interpreted as a valid directory, Python file,
        or PyPI package, a dictionary with an ``"Error"`` key is returned.

    Raises:
        None explicitly. Any unexpected exceptions are allowed to propagate
        unless handled by downstream callers.

    Example:
        >>> result = filescan("example_package")
        >>> result["package_name"]
        
    """
    file_output = {}
    file_path = Path(input_path)
    ca_version_info = version()
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on" : timestamp_str}    
    # Check if the input is a valid directory or a single valid Python file
    if file_path.is_dir(): #local directory scan
        package_name = get_filename_from_path(input_path)
        output |= {"package_name": package_name}
        scan_output = _codeaudit_directory_scan(input_path)
        output |= scan_output
        return output            
    elif file_path.suffix.lower() == ".py" and file_path.is_file() and is_ast_parsable(input_path):   #check on parseable single Python file   
        # do a file check
        file_information = overview_per_file(input_path) 
        module_information = get_modules(input_path) # modules per file
        scan_output = _codeaudit_scan(input_path)                
        file_output["0"] = file_information | module_information | scan_output #there is only 1 file , so index 0 equals as for package to make functionality that use the output that works on the dict or json can equal for a package or a single file!
        output |= { "file_security_info" : file_output}
        return output
    elif (pypi_data := get_pypi_download_info(input_path)):    
        package_name = input_path #The variable input_path is now equal to the package name        
        url = pypi_data['download_url']
        release = pypi_data['release']
        if url is not None:
            src_dir, tmp_handle = get_package_source(url)            
            output |= {"package_name": package_name,
                       "package_release": release}
            try:
                scan_output = _codeaudit_directory_scan(src_dir)
                output |= scan_output
            finally:
                # Cleaning up temp directory
                tmp_handle.cleanup()  # deletes everything from temp directory
            return output
    else:
        # Its not a directory nor a valid Python file:
        return {"Error" : "File is not a *.py file, does not exist or is not a valid directory path towards a Python package."}

def _codeaudit_scan(filename):
    """Internal helper function to do a SAST scan on a single file
    To scan a file, or Python package using the API interface, use the `filescan` API call!
    """
    #get the file name
    name_of_file = get_filename_from_path(filename)
    sast_data = perform_validations(filename)
    sast_data_results = sast_data["result"]    
    sast_result = dict(sorted(sast_data_results.items()))
    output = { "file_name" : name_of_file ,
              "sast_result": sast_result}    
    return output

def _codeaudit_directory_scan(input_path):
    """Performs a scan on a local directory
    Function is also used with scanning directory PyPI.org packages, since in that case a tmp directory is used
    """
    output ={}
    file_output = {}
    files_to_check = collect_python_source_files(input_path)    
    if len(files_to_check) > 1:
        modules_discovered = get_all_modules(input_path) #all modules for the package aka directory        
        package_overview = get_overview(input_path)
        output |= {"statistics_overview" : package_overview ,
                   "module_overview" : modules_discovered }        
        for i,file in enumerate(files_to_check):
            file_information = overview_per_file(file)
            module_information = get_modules(file) # modules per file            
            scan_output = _codeaudit_scan(file)
            file_output[i] = file_information | module_information | scan_output
        output |= { "file_security_info" : file_output}
        return output
    else:
        output_msg = f'Directory path {input_path} contains no Python files.'
        return {"Error" : output_msg}


def save_to_json(sast_result, filename="codeaudit_output.json"):
    """
    Save a SAST result (dict or serializable object) to a JSON file.

    Args:
        sast_result (dict or list): The data to be saved as JSON.
        filename (str, optional): The file path to save the JSON data.
            Defaults to "codeaudit_output.json".

    Returns:
        Path: The absolute path of the saved file, or None if saving failed.
    """
    filepath = Path(filename).expanduser().resolve()

    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)  # ensure directory exists
        with filepath.open("w", encoding="utf-8") as f:
            json.dump(sast_result, f, indent=2, ensure_ascii=False)
        return
    except (TypeError, ValueError) as e:
        print(f"[Error] Failed to serialize data to JSON: {e}")
    except OSError as e:
        print(f"[Error] Failed to write file '{filepath}': {e}")

def read_input_file(filename):
    """
    Read a Python CodeAudit JSON file and return its contents as a Python dictionary.
    
    Args:
        filename: Path to the JSON file.
        
    Returns:
        dict: The contents of the JSON file.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {filename}") from e
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in file: {filename}", e.doc, e.pos)


def get_construct_counts(input_file):
    """
    Analyze a Python file or package(directory) and count occurrences of code constructs (aka weaknesses).

    This function uses `filescan` API call to retrieve security-related information
    about the input file. This returns a dict. Then it counts how many times each code construct
    appears across all scanned files.

    Args:
        input_file (str): Path to the file or directory(package) to scan.

    Returns:
        dict: A dictionary mapping each construct name (str) to the total
              number of occurrences (int) across all scanned files.

    Notes:
        - The `filescan` function is expected to return a dictionary with
          a 'file_security_info' key, containing per-file information.
        - Each file's 'sast_result' should be a dictionary mapping
          construct names to lists of occurrences.
    """    
    scan_result = filescan(input_file)
    counter = Counter()
    
    for file_info in scan_result.get('file_security_info', {}).values():
        sast_result = file_info.get('sast_result', {})
        for construct, occurence in sast_result.items(): #occurence is times the construct appears in a single file
            counter[construct] += len(occurence)
    
    return dict(counter)

def get_modules(filename):
    """Gets modules of a Python file """
    modules_found = get_imported_modules_by_file(filename)
    return modules_found

def get_overview(input_path):
    """Retrieves the security relevant statistics of a Python package(directory) or of a single Python 

    Based on the input path, call the overview function and return the result in a dict

    Args:
        input_path: Directory path of the package to use
        

    Returns:
        dict: Returns the overview statistics in DICT format
    """
    file_path = Path(input_path)
    if file_path.is_dir(): #only for valid parsable Python files
        files_to_check = collect_python_source_files(input_path)        
        if len(files_to_check) > 1:
            statistics = get_statistics(input_path)
            modules = total_modules(input_path)
            df = pd.DataFrame(statistics) 
            df['Std-Modules'] = modules['Std-Modules'] #Needed for the correct overall count
            df['External-Modules'] = modules['External-Modules'] #Needed for the correct overall count
            overview_df = overview_count(df) #create the overview Dataframe
            dict_overview = overview_df.to_dict(orient="records")[0] #The overview Dataframe has only one row
            return dict_overview
        else:
            output_msg = f'Directory path {input_path} contains no Python files.'
            return {"Error" : output_msg}
    elif file_path.suffix.lower() == ".py" and file_path.is_file() and is_ast_parsable(input_path):
        security_statistics = overview_per_file(input_path)
        return security_statistics
    else:
        #Its not a directory nor a valid Python file:
        return {"Error" : "File is not a *.py file, does not exist or is not a valid directory path to a Python package."}

def get_default_validations():
    """Retrieve the default implemented security validations.

    This function collects the built-in Static Application Security Testing (SAST)
    validations applied to standard Python modules. It retrieves the validation
    definitions, converts them into a serializable format, and enriches the result
    with generation metadata.

    The returned structure is intended to be consumed by reporting, API, or
    documentation layers.

    Returns:
        dict: A dictionary containing generation metadata and a list of security
        validations. The dictionary has the following structure:

        {
            "<metadata_key>": <metadata_value>,
            ...,
            "validations": [
                {
                    "<field>": <value>,
                    ...
                },
                ...
            ]
        }

    
    **Notes**:
    
        - Requires Python 3.9 or later due to use of the dictionary union operator (`|`).
        - The `validations` list is derived from a pandas DataFrame using
          `to_dict(orient="records")`.
    """
    df = ast_security_checks()
    result = df.to_dict(orient="records")    
    output = _generation_info() | {"validations" : result}
    return output

def _generation_info():
    """Internal function to retrieve generation info for APIs output"""
    ca_version_info = version()    
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on" : timestamp_str}
    return output

def platform_info():
    """Get Python platform information - Python version and Python runtime interpreter used.
    Args:
        none

    Returns:
        dict: Overview of implemented security SAST validation on Standard Python modules       
    """
    python_version = platform.python_version()
    platform_implementation = platform.python_implementation()
    output = { "python_version" : python_version ,
              "python_implementation" : platform_implementation}
    return output


def get_psl_modules():
    """Retrieves a list of  collection of Python modules that are part of a Python distribution aka standard installation
    
    Returns:
        dict: Overview of PSL modules in the Python version used.
    
    """
    psl_modules = get_standard_library_modules()
    output = _generation_info() | platform_info() | { "psl_modules" : psl_modules}
    return output

def get_module_vulnerability_info(module):
    """
    Retrieves vulnerability information for an external module using the OSV Database.

    Args:
        module (str): Name of the module to query.

    Returns:
        dict: Generation metadata combined with OSV vulnerability results.
    """    
    vuln_info = check_module_vulnerability(module)
    key_string = f'{module}_vulnerability_info'
    output = _generation_info() | { key_string : vuln_info}
    return output
