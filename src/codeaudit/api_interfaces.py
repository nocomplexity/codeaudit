"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


Public API functions for Python Code Audit aka codeaudit on pypi.org
"""

from codeaudit import __version__
from codeaudit.filehelpfunctions import get_filename_from_path , collect_python_source_files 
from codeaudit.security_checks import perform_validations
from codeaudit.totals import overview_per_file 
from codeaudit.checkmodules import get_all_modules , get_imported_modules_by_file


from pathlib import Path
import json
import datetime 

def version():
    """Returns the version of Python Code Audit"""
    ca_version = __version__
    return {"name" : "Python_Code_Audit",
             "version" : ca_version}


def filescan(input_path):
    """Scans a Python file or directory and returns result as JSON"""    
    output ={}
    file_output = {}
    file_path = Path(input_path)
    ca_version_info = version()
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on" : timestamp_str}    
    # Check if the input is a valid directory or a single valid Python file
    if file_path.is_dir():
        files_to_check = collect_python_source_files(input_path)
        modules_discovered = get_all_modules(input_path) #all modules for the package aka directory
        name_of_package = get_filename_from_path(input_path)
        output |= {"package_name" : name_of_package ,
                   "module_overview" : modules_discovered }        
        for i,file in enumerate(files_to_check):            
            file_information = overview_per_file(file)
            module_information = get_modules(file) # modules per file            
            scan_output = codeaudit_scan(file)
            file_output[i] = file_information | module_information | scan_output
        output |= { "file_security_info" : file_output}
        return output
    elif file_path.suffix == ".py" and file_path.is_file():        
        #do a file check                        
        file_information = overview_per_file(input_path) 
        module_information = get_modules(input_path) # modules per file
        scan_output = codeaudit_scan(input_path)                
        file_output[0] = file_information | module_information | scan_output #there is only 1 file , so index 0
        output |= { "file_security_info" : file_output}
        return output
    else:
        #Its not a directory nor a valid Python file:
        return {"Error" : "File is not a *.py file, does not exist or is not a valid directory path."}

def codeaudit_scan(filename):
    """Function to do a SAST scan on a single file"""
    #get the file name
    name_of_file = get_filename_from_path(filename)
    sast_data = perform_validations(filename)
    sast_data_results = sast_data["result"]    
    sast_result = dict(sorted(sast_data_results.items()))
    output = { "file_name" : name_of_file ,
              "sast_result": sast_result}    
    return output


def save_to_json(sast_result, filename="sast_fileoutput.json"):
    """Saves CA dict to a json file
    Convert the SAST object to a JSON string
    """
    json_output = json.dumps(sast_result)
    with open("sast_fileoutput.json", "w") as f:
        f.write(json_output)
    return 

def get_modules(filename):
    """Gets modules of a Python file """
    modules_found = get_imported_modules_by_file(filename)
    return modules_found