"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


CLI functions for codeaudit
"""
import fire  # for working CLI with this PoC-thing (The Google way)
import sys
from codeaudit import __version__
from codeaudit.reporting import overview_report ,report_module_information ,file_scan_report , directory_scan_report , report_implemented_tests

codeaudit_ascii_art=r"""
--------------------------------------------------
   _____          _                      _ _ _   
  / ____|        | |                    | (_) |  
 | |     ___   __| | ___  __ _ _   _  __| |_| |_ 
 | |    / _ \ / _` |/ _ \/ _` | | | |/ _` | | __|
 | |___| (_) | (_| |  __/ (_| | |_| | (_| | | |_ 
  \_____\___/ \__,_|\___|\__,_|\__,_|\__,_|_|\__|
--------------------------------------------------
"""
     

def display_version():
    """Prints the module version. Use [-v] [--v] [-version] or [--version]."""
    print(f"version: {__version__}")


def display_help():
    """Shows detailed help for using codeaudit tool."""    
    print(codeaudit_ascii_art)
    print("Codeaudit - Modern Python source code analyzer based on distrust.\n")
    print("Commands to evaluate Python source code:")
    print('Usage: codeaudit COMMAND [PATH or FILE]  [OUTPUTFILE] \n')
    print('Depending on the command, a directory or file name must be specified. The output is a static HTML file to be examined in a browser. Specifying a name for the output file is optional.\n')
    print('Commands:')
    commands = ["overview", "directoryscan", "filescan", "modulescan",  "checks","version"]  # commands on CLI
    functions = [overview_report, directory_scan_report, file_scan_report, report_module_information, report_implemented_tests,display_version]  # Related functions relevant for help
    for command, function in zip(commands, functions):
        docstring = function.__doc__.strip().split('\n')[0] or ""  
        summary = docstring.split("\n", 1)[0]
        print(f"  {command:<20} {summary}")        
    print("\nUse the Codeaudit documentation to check the security of Python programs and make your Python programs more secure!\nCheck https://simplifysecurity.nocomplexity.com/ \n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-v", "--v", "--version", "-version"):
        display_version()
    elif len(sys.argv) > 1 and sys.argv[1] in ("-help", "-?", "--help", "-h"):
        display_help()
    elif len(sys.argv) == 1:
        display_help()
    else:
        fire.Fire(
            {
                "overview": overview_report,               
                "modulescan": report_module_information,
                "filescan" : file_scan_report,
                "directoryscan" : directory_scan_report,
                "checks" : report_implemented_tests,
                "-help": display_help,
            }
        )


if __name__ == "__main__":
    main()

                                            
                                                 

