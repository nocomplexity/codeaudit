"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 

The checks for codeaudit
"""

import pandas as pd

from codeaudit.filehelpfunctions import read_in_source_file , get_filename_from_path 
from codeaudit.issuevalidations import find_constructs


from importlib.resources import files


def load_sast_checks():
    csv_path = files("codeaudit.data").joinpath("sastchecks.csv")
    return pd.read_csv(csv_path)


def ast_security_checks():
    """Loads the SAST checks and return a Dataframe with all security checks that are implemented on AST level"""
    df_sastchecks = load_sast_checks() # The checks are packaged with codeaudit 
    if not df_sastchecks['construct'].is_unique:  #The construct column items MUST be unique!
        duplicates = df_sastchecks['construct'][df_sastchecks['construct'].duplicated()]
        print("Duplicate 'construct' values found:")
        print(duplicates)
        exit(1) #Something wrong with added new test!
    return df_sastchecks
    


def perform_validations(sourcefile):
    """For now a list defined here in this file"""
    checks = ast_security_checks()
    #df = pd.DataFrame(security_validations)
    constructs = checks['construct'].to_list()
    
    source = read_in_source_file(sourcefile)
    scan_result = find_constructs(source, constructs)
    

    name_of_file = get_filename_from_path (sourcefile)
    
    result = {'Name file' : name_of_file ,
              'file_location': sourcefile ,
              'Checks done:' : constructs ,
              'result': scan_result}

    return result
