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
from codeaudit.security_checks import perform_validations , ast_security_checks
from codeaudit.totals import overview_per_file , get_statistics , overview_count , total_modules
from codeaudit.checkmodules import get_all_modules , get_imported_modules_by_file


from pathlib import Path
import json
import datetime 
import pandas as pd

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
        if len(files_to_check) > 1:
            modules_discovered = get_all_modules(input_path) #all modules for the package aka directory
            name_of_package = get_filename_from_path(input_path)
            package_overview = get_overview(input_path)
            output |= {"package_name" : name_of_package ,
                    "statistics_overview" : package_overview ,
                    "module_overview" : modules_discovered }        
            for i,file in enumerate(files_to_check):            
                file_information = overview_per_file(file)
                module_information = get_modules(file) # modules per file            
                scan_output = codeaudit_scan(file)
                file_output[i] = file_information | module_information | scan_output
            output |= { "file_security_info" : file_output}
            return output
        else:
            output_msg = f'Directory path {input_path} contains no Python files.'
            return {"Error" : output_msg}
    elif file_path.suffix.lower() == ".py" and file_path.is_file():        
        #do a file check                        
        file_information = overview_per_file(input_path) 
        module_information = get_modules(input_path) # modules per file
        scan_output = codeaudit_scan(input_path)                
        file_output[0] = file_information | module_information | scan_output #there is only 1 file , so index 0 equals as for package to make functionality that use the output that works on the dict or json can equal for a package or a single file!
        output |= { "file_security_info" : file_output}
        return output
    else:
        #Its not a directory nor a valid Python file:
        return {"Error" : "File is not a *.py file, does not exist or is not a valid directory path towards a Python package."}

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
    with open(filename, "w") as f:
        f.write(json_output)
    return 

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
    if file_path.is_dir():
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
    elif file_path.suffix.lower() == ".py" and file_path.is_file():
        security_statistics = overview_per_file(input_path)
        return security_statistics
    else:
        #Its not a directory nor a valid Python file:
        return {"Error" : "File is not a *.py file, does not exist or is not a valid directory path to a Python package."}

def get_default_validations():
    """Retrieves the implemented default security validations
    Args:
        none

    Returns:
        dict: Overview of implemented security SAST validation on Standard Python modules
    """
    ca_version_info = version()
    df = ast_security_checks()
    result = df.to_dict(orient="records")
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on" : timestamp_str} | {"validations" : result}
    return output