"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
Validation file to see if SAST suppression works correct.

"""


self.process = subprocess.Popen('/bin/rmdir', shell=True)  # nosec
self.process = subprocess.Popen( 
    '/bin/rmdir', #nosec nosec nosec
      shell=True)  


import builtins
number = input("number to find a security issue?") #nosec
d = builtins
code_obj = d.compile('x = 5*5\nprint(x)', '<string>', 'exec') #nosec
result = d.exec(code_obj)  #Input should not be obfuscated. Code Audit will detect this! nosec


number = input("number to find a security issue?") #nosec
d = builtins #nosec
code_obj = d.compile("x = 5*5\nprint(x)", #nosec
                     "<string>", "exec")
result = d.exec(code_obj)  #Input should not be obfuscated. Code Audit will detect this! # nosec

import shelve
# line belows also is a weakness, since shelve uses the pickle module
db = shelve.DbfilenameShelf("mydata.db", 
                            flag="c", 
                            protocol=None, writeback=False) #nosec
