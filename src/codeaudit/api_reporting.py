"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


Public API functions for Python Code Audit aka codeaudit on pypi.org

All reporting API functions are created based on the Code Audit JSON format that is used when scan results are stored using the `codeaudit.api_interfaces.save_to_json` call!

These API functions are on purpose opinionated for one goal: Keep things simple!
So all results are returned as Pandas Dataframe. This makes things easier for further processing!

"""
import pandas as pd
from collections import Counter

def total_weaknesses(input_file):
    """Returns the total weaknesses found"""
    scan_result = input_file
    counter = Counter()
    
    for file_info in scan_result.get('file_security_info', {}).values():
        sast_result = file_info.get('sast_result', {})
        for construct, occurence in sast_result.items(): #occurence is times the construct appears in a single file
            counter[construct] += len(occurence)
    
    result = dict(counter)
    df = pd.DataFrame(list(result.items()), columns=['call', 'count'])
    return df