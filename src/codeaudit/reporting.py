"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


Reporting functions for codeaudit
"""

import re
import os
from pathlib import Path

import pandas as pd
import html
import datetime

from codeaudit.security_checks import perform_validations , ast_security_checks
from codeaudit.filehelpfunctions import get_filename_from_path , collect_python_source_files , read_in_source_file , has_python_files , is_ast_parsable
from codeaudit.altairplots import multi_bar_chart
from codeaudit.totals import get_statistics , overview_count , overview_per_file , total_modules
from codeaudit.checkmodules import get_imported_modules , check_module_vulnerability , get_all_modules , get_imported_modules_by_file
from codeaudit.htmlhelpfunctions import json_to_html , dict_list_to_html_table
from codeaudit import __version__
from codeaudit.pypi_package_scan import get_pypi_download_info , get_package_source
from codeaudit.privacy_lint import secret_scan , has_privacy_findings

from importlib.resources import files


PYTHON_CODE_AUDIT_TEXT = '<a href="https://github.com/nocomplexity/codeaudit" target="_blank"><b>Python Code Audit</b></a>'
DISCLAIMER_TEXT = (
    "<p><b>Disclaimer:</b> <i>This SAST tool "
    + PYTHON_CODE_AUDIT_TEXT
    + " provides a powerful, automatic security analysis for Python source code. However, it's not a substitute for human review in combination with business knowledge. Undetected vulnerabilities may still exist.</i></p>"
)


SIMPLE_CSS_FILE = files('codeaudit') / 'simple.css'

DEFAULT_OUTPUT_FILE = 'codeaudit-report.html'

def overview_report(directory, filename=DEFAULT_OUTPUT_FILE):
    """Generates an overview report of code complexity and security indicators.

    This function analyzes a Python project to produce a high-level overview of
    complexity and security-related metrics. The input may be either:

    - A local directory containing Python source files
    - The name of a package hosted on PyPI.org

    So:
    codeaudit overview <package-name|directory> [reportname.html]

    For PyPI packages, the source distribution (sdist) is downloaded,
    extracted to a temporary directory, scanned, and removed after the report
    is generated.

    The report includes summary statistics, security risk indicators based on
    complexity and total lines of code, a list of discovered modules, per-file
    metrics, and a visual overview. Results are written to a static HTML file.
    
    Examples:
        Generate an overview report for a local project directory::

            codeaudit overview /projects/mycolleaguesproject

        Generate an overview report for a PyPI package::

            codeaudit overview linkaudit #A nice project on PyPI.org

            codeaudit overview pydantic  #A complex project on PyPI.org from a security perspective?

    Args:
        directory (str): Path to a local directory containing Python source files
            or the name of a package available on PyPI.org.
        filename (str, optional): Name (and optional path) of the HTML file to
            write the overview report to. The filename should use the ``.html``
            extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

    Returns:
        None. The function writes a static HTML overview report to disk.

    Raises:
        SystemExit: If the provided path is not a directory, contains no Python
            files, or is neither a valid local directory nor a valid PyPI
            package name.    
    """
    clean_up = False
    advice = None
    if os.path.exists(directory):
        # Check if the path is actually a directory
        if not os.path.isdir(directory):
            print(f"ERROR: '{directory}' is not a directory.")
            print("This function only works for directories containing Python files (*.py).")
            exit(1)      
        # Check if the directory contains any .py files
        if not has_python_files(directory):
            print(f"ERROR: Directory '{directory}' contains no Python files.")
            exit(1)
    elif get_pypi_download_info(directory):
        # If local path doesn't exist, try to treat it as a PyPI package
        print(f"No local directory with name:{directory} found locally. Checking if package exist on PyPI...")  
        package_name = directory #The variable input_path is now equal to the package name
        print(f"Package: {package_name} exist on PyPI.org!")        
        pypi_data = get_pypi_download_info(package_name)
        url = pypi_data['download_url']
        release = pypi_data['release']
        advice = f'<p>&#128073; To perform a SAST scan on the source code, run:<pre><code class="language-python">codeaudit filescan {package_name}</code></pre></p>'
        if url is not None:
            print(f'Creating Python Code Audit overview for package:\n{url}')            
            src_dir, tmp_handle = get_package_source(url)                    
            directory = src_dir
            clean_up = True            
    else:
        # Neither a local directory nor a valid PyPI package
        print(f"ERROR: '{directory}' is not a local directory or a valid PyPI package.")
        exit(1)    
    result = get_statistics(directory)
    modules = total_modules(directory)    
    df = pd.DataFrame(result)
    df['Std-Modules'] = modules['Std-Modules']
    df['External-Modules'] = modules['External-Modules']
    overview_df = overview_count(df)
    output = '<h1>' + f'Python Code Audit overview report' + '</h1><br>'
    if clean_up:
        output += f'<p>Codeaudit overview scan of package:<b> {package_name}</b></p>' 
        output += f'<p>Version:<b>{release}</b></p>'
    else:
        output += f'<p>Overview for the directory:<b> {directory}</b></p>' 
    output += f'<h2>Summary</h2>'
    output += overview_df.to_html(escape=True,index=False)
    output += '<br><br>'
    security_based_on_max_complexity = overview_df.loc[0,'Maximum_Complexity']
    if security_based_on_max_complexity > 40:        
        output += '<p>Based on the maximum found complexity in a source file: Security concern rate is <b>&#10060; HIGH</b>.'
    else:
        output += '<p>Based on the maximum found complexity in a source file: Security concern rate is <b>&#x2705; LOW</b>.'
    security_based_on_loc = overview_df.loc[0,'Number_Of_Lines']
    if security_based_on_loc > 2000:
        output += '<p>Based on the total Lines of Code (LoC) : Security concern rate is <b>&#10060; HIGH</b>.'
    else:
        output += '<p>Based on the total Lines of Code (LoC) : Security concern rate is <b>&#x2705; LOW</b>.'
    output += '<br>'
    ## Module overview
    modules_discovered = get_all_modules(directory)    
    if clean_up:
        tmp_handle.cleanup() #Clean up tmp directory if overview is created directly from PyPI package
    output += '<details>' 
    output += '<summary>View all discovered modules.</summary>'
    output += display_found_modules(modules_discovered)    
    output += '</details>'           
    output += f'<h2>Detailed overview per source file</h2>'
    output += '<details>'     
    output += '<summary>View the report details.</summary>'
    df_plot = pd.DataFrame(result) # again make the df from the result variable         
    output += df_plot.to_html(escape=True,index=False)        
    output += '</details>'           
    # I now want only a plot for LoC, so drop other columns from Dataframe
    df_plot = pd.DataFrame(result) # again make the df from the result variable
    df_plot = df_plot.drop(columns=['FilePath'])
    plot = multi_bar_chart(df_plot)
    plot_html = plot.to_html()    
    output += '<br><br>'
    output += '<h2>Visual Overview</h2>'    
    output += extract_altair_html(plot_html)
    output += '<p><b>&#128172; Advice:</b></p>'
    if advice is not None and advice != "":    
        output += advice
    else:
        output += f'<p>&#128073; To perform a SAST scan on the source code, run:<pre><code class="language-python">codeaudit filescan {directory}</code></pre></p>'    
    create_htmlfile(output,filename)


def display_found_modules(modules_discovered):
    """Formats discovered Python modules into an HTML string.

    Args:
        modules_discovered (dict): Dictionary containing discovered modules with
            keys 'core_modules' and 'imported_modules', each mapping to an
            iterable of module names.

    Returns:
        str: HTML-formatted string listing standard library modules and
        imported external packages.
    """
    core_modules = modules_discovered["core_modules"]
    external_modules = modules_discovered["imported_modules"]
    output = "<p><b>Used Python Standard libraries:</b></p>"
    output += (
        "<ul>\n"
        + "\n".join(f"  <li>{module}</li>" for module in core_modules)
        + "\n</ul>"
    )
    output += "<p><b>Imported libraries (packages):</b></p>"
    output += (
        "<ul>\n"
        + "\n".join(f"  <li>{module}</li>" for module in external_modules)
        + "\n</ul>"
    )
    return output


def scan_report(input_path, filename=DEFAULT_OUTPUT_FILE):
    """Scans Python source code or PyPI packages for security weaknesses.

    This function performs static application security testing (SAST) on a
    given input, which can be:

    - A local directory containing Python source code
    - A single local Python file 
    - A package name hosted on PyPI.org

    codeaudit filescan <pythonfile|package-name|directory> [reportname.html]

    Depending on the input type, the function analyzes the source code for
    potential security issues, generates an HTML report summarizing the
    findings, and writes the report to a static HTML file.

    If a PyPI package name is provided, the function downloads the source
    distribution (sdist), scans the extracted source code, and removes all
    temporary files after the scan completes.

    Example:
        Scan a local directory and write the report to ``report.html``::

            codeaudit filescan_/shitwork/custompythonmodule/ 

        Scan a single Python file::

            codeaudit filescan myexample.py

        Scan a package hosted on PyPI::

            codeaudit filescan linkaudit  #A nice project to check broken links in markdown files

            codeaudit filescan requests

    Args:
        input_path (str): Path to a local Python file or directory, or the name
            of a package available on PyPI.org.
        filename (str, optional): Name (and optional path) of the HTML file to
            write the scan report to. The filename should use the ``.html``
            extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

    Returns:
        None. The function writes a static HTML security report to disk.

    Raises:
        None explicitly. Errors and invalid inputs are reported to stdout.    
    """
    # Check if the input is a valid directory or a single valid Python file 
    # In case no local file or directory is found, check if the givin input is pypi package name
    file_path = Path(input_path)
    if file_path.is_dir():
        directory_scan_report(input_path , filename ) #create a package aka directory scan report
    elif file_path.suffix == ".py" and file_path.is_file() and is_ast_parsable(input_path):        
        #create a sast file check report
        scan_output = perform_validations(input_path) #scans for weaknesses in the file
        spy_output = secret_scan(input_path) #scans for secrets in the file
        file_report_html = single_file_report(input_path , scan_output)
        secrets_report_html = secrets_report(spy_output)
        name_of_file = get_filename_from_path(input_path)
        html_output = '<h1>Python Code Audit Report</h1>' #prepared to be embedded to display multiple reports, so <h2> used
        html_output += f'<h2>Security scan: {name_of_file}</h2>'    
        html_output += '<p>' + f'Location of the file: {input_path} </p>'  
        html_output += file_report_html    
        html_output += secrets_report_html    
        html_output += '<br>'
        html_output += DISCLAIMER_TEXT
        create_htmlfile(html_output,filename)
    elif get_pypi_download_info(input_path):
        package_name = input_path #The variable input_path is now equal to the package name
        print(f"Package: {package_name} exist on PyPI.org!")
        print(f"Now SAST scanning package from the remote location: https://pypi.org/pypi/{package_name}")        
        pypi_data = get_pypi_download_info(package_name)
        url = pypi_data['download_url']
        release = pypi_data['release']
        if url is not None:
            print(url)
            print(release)
            src_dir, tmp_handle = get_package_source(url)
            directory_scan_report(src_dir , filename , package_name, release ) #create scan report for a package or directory
            # Cleaning up temp directory 
            tmp_handle.cleanup()  # deletes everything from temp directory
        else:
            print(f'Error:A source distribution (sdist in .tar.gz format) for package: {package_name} can not be found or does not exist on PyPi.org.\n')
            print(f"Make a local git clone of the {package_name} using `git clone` and run `codeaudit filescan <directory-with-src-cloned-of-{package_name}>` to check for weaknesses.")
    else:
        #File is NOT a valid Python file, can not be parsed or directory is invalid.
        print(f"Error: '{input_path}' isn't a valid Python file, directory path to a package or a package on PyPI.org.")

def secrets_report(spy_output):
    """
    Generate an HTML report section for detected secrets and external egress risks.

    This function analyzes the provided static analysis output to determine
    whether logic for connecting to external or remote services is present.
    If such logic is detected, it generates an HTML report section describing
    the potential external egress risk and includes a detailed, tabular analysis
    of where connection-related variables are used. If no such logic is found,
    a success message indicating low data exfiltration risk is returned.

    Args:
        filename (str): Name of the file being analyzed. This parameter is used
            for contextual identification and reporting purposes.
        spy_output (object): Output from the secrets or static analysis process
            containing findings used to detect external service connections.

    Returns:
        str: An HTML string representing the secrets and external egress risk
        report section.
    """    
    if has_privacy_findings(spy_output):
        output = '<br><p>&#9888;&#65039; <b>External Egress Risk</b>: Possible API keys or logic for connecting to remote services found.</p>'
        output += '<details>'
        output += '<summary>View detailed analysis for suspected locations where secrets are found or used in the code.</summary>'        
        pylint_df = pylint_reporting(spy_output)
        output += pylint_df.to_html(escape=False,index=False) 
        output += '</details>'
        output += '<br>'   
    else:        
        output = f'<br><p>&#x2705; No Logic for connecting to remote services found. Risk of data exfiltration to external systems is <b>low</b>.</p>'
    return output


def pylint_reporting(result):
    """
    Creates a pandas DataFrame of privacy findings with columns:
    'lineno' and 'code'.
    HTML-escaped and newlines converted to <br> for safe display.
    """
    rows = []

    # Check that file_privacy_check exists and is not empty
    if result.get("file_privacy_check"):
        for item in result["file_privacy_check"].values():
            for entry in item.get("privacy_check_result", []):
                # Escape HTML special characters
                escaped_code = html.escape(entry["code"])
                # Convert newlines to <br> and wrap in <pre><code>
                code_html = f'<pre><code class="language-python">{escaped_code.replace("\n", "<br>")}</code></pre>'
                # Add a row to the list
                rows.append({
                    "lineno": entry["lineno"],
                    "matched" : entry["matched"],
                    "code": code_html
                })

    # Convert to pandas DataFrame
    df = pd.DataFrame(rows, columns=["lineno", "matched", "code"])
    df = df.rename(columns={"lineno": "line", "matched": "found"}) #rename to UI frienly names

    return df


def single_file_report(filename , scan_output):
    """Function to DRY for a codescan when used for single for CLI or within a directory scan"""
    data = scan_output["result"]    
    df = pd.DataFrame(
        [(key, lineno) for key, linenos in data.items() for lineno in linenos],
        columns=["validation", "line"],
    )
    number_of_issues = len(df)
    df['severity'] = None
    df['info'] = None
    for error_str in data:
        severity, info_text = get_info_on_test(error_str)            
        matching_rows = df[df['validation'] == error_str]
        if not matching_rows.empty:
            # Update all matching rows
            df.loc[matching_rows.index, ['severity', 'info']] = [severity, info_text]        
    df['code'] = None
    filename_location = scan_output["file_location"]
    for idx, row in df.iterrows():
        line_num = row['line']
        df.at[idx, 'code'] = collect_issue_lines(filename_location, line_num)        

    df['code'] = df['code'].str.replace(r'\n', '<br>', regex=True)  # to convert \n to \\n for display    
    df['validation'] = df['validation'].apply(replace_second_dot) #Make the validation column smaller - this is the simplest way! without using styling options from Pandas!
    df = df[["line", "validation", "severity", "info", "code"]] # reorder the columns before converting to html
    df = df.sort_values(by="line") # sort by line number 
    if number_of_issues > 0:
        output = f'<p>&#9888;&#65039; <b>{number_of_issues}</b> potential <b>security issues</b> found!</p>'
        output += '<details>'
        output += '<summary>View identified security weaknesses.</summary>'    
        output += df.to_html(escape=False,index=False)        
        output += '</details>'
        output += '<br>'
    else:
        output = '' # No weaknesses found, no message, since privacy breaches may be present.        
    file_overview = overview_per_file(filename)    
    df_overview = pd.DataFrame([file_overview])    
    output += '<details>'     
    output += f'<summary>View detailed analysis of security relevant file details.</summary>'                 
    output += df_overview.to_html(escape=True,index=False)        
    output += '</details>'
    output += '<br>'
    output += '<details>' 
    output += '<summary>View used modules in this file.</summary>' 
    modules_found = get_imported_modules_by_file(filename)
    output += display_found_modules(modules_found)    
    output += f'<p>To check for <b>reported vulnerabilities</b> in external modules used by this file, use the command:<br><div class="code-box">codeaudit modulescan {filename}</div><br></p>'     
    output += '</details>'           
    return output 


def directory_scan_report(directory_to_scan , filename=DEFAULT_OUTPUT_FILE , package_name=None , release=None):
    """Reports potential security issues for all Python files found in a directory.
    
    This function performs security validations on all files found in a specified directory.
    The result is written to a HTML report. 
    
    You can specify the name and directory for the generated HTML report.

    Parameters:
        directory_to_scan (str)      : The full path to the Python source files to be scanned. Can be present in temp directory.
        filename (str, optional): The name of the HTML file to save the report to.
                                  Defaults to `DEFAULT_OUTPUT_FILE`.

    Returns:
        None - A HTML report is written as output
    """
     # Check if the provided path is a valid directory
    if not os.path.isdir(directory_to_scan):
        print(f"Error: '{directory_to_scan}' is not a valid directory.")
        exit(1) 

    collection_ok_files = [] # create a collection of files with no issues found    
    output = '<h1>Python Code Audit Report</h1>'     
    files_to_check = collect_python_source_files(directory_to_scan)
    output += '<h2>Directory scan report</h2>'         
    name_of_package = get_filename_from_path(directory_to_scan)
    if package_name is not None:
        #Use real package name and retrieved release info
        output += f'<p>Below the result of the Codeaudit scan of (Package name - Release):</p>'
        output += f'<p><b> {package_name} - {release} </b></p>'
    else:
        output += f'<p>Below the result of the Codeaudit scan of the directory:<b> {name_of_package}</b></p>' 
    output += f'<p>Total Python files found: <b>{len(files_to_check)}</b></p>'
    number_of_files = len(files_to_check)
    print(f'Number of files that are checked for security issues:{number_of_files}')
    printProgressBar(0, number_of_files, prefix='Progress:', suffix='Complete', length=50)    
    for i,file_to_scan in enumerate(files_to_check):
        printProgressBar(i + 1, number_of_files, prefix='Progress:', suffix='Complete', length=50)
        scan_output = perform_validations(file_to_scan)
        spy_output = secret_scan(file_to_scan) #scans for secrets in the file 
        data = scan_output["result"]
        if data or has_privacy_findings(spy_output):
            file_report_html = single_file_report(file_to_scan , scan_output)             
            name_of_file = get_filename_from_path(file_to_scan)            
            output += f'<h3>Security scan: {name_of_file}</h3>'    
            if package_name is None:
                output += '<p>' + f'Location of the file: {file_to_scan} </p>'          
            output += file_report_html 
            secrets_report_html = secrets_report(spy_output)
            output += secrets_report_html                     
        else:
            file_name_with_no_issue = get_filename_from_path(file_to_scan)
            collection_ok_files.append({'filename' : file_name_with_no_issue ,
                                        'directory': file_to_scan})        
    output += '<h2>Files in directory with no security issues</h2>'
    output += f'<p>&#x2705; Total Python files <b>without</b> detected security issues: {len(collection_ok_files)}</p>'
    output += '<p>The Python files with no security issues <b>detected</b> by codeaudit are:<p>'        
    output += dict_list_to_html_table(collection_ok_files)     
    output += '<br>'
    if package_name is not None:
        output += f'<p><b>Note:</b><i>Since this check is done on a package on PyPI.org, the temporary local directories are deleted. To examine the package in detail, you should download the sources locally and run the command:<code>codeaudit filescan</code> again.</i></p>'
    output += '<p><b>Disclaimer:</b><i>This scan only evaluates Python files. Please note that security vulnerabilities may also exist in other files associated with the Python module.</i></p>'
    output += DISCLAIMER_TEXT
    create_htmlfile(output,filename)  


def report_module_information(inputfile, reportname=DEFAULT_OUTPUT_FILE):
    """
    Generate a report on known vulnerabilities in Python modules and packages.

    This function analyzes a single Python file to identify imported
    external modules and checks those modules against the OSV vulnerability
    database. The collected results are written to a static HTML report.

    If the input refers to a valid PyPI package name instead of a local Python
    file, the function generates a vulnerability report directly for that
    package.

    While processing modules, progress information is printed to standard
    output.

    Example:
        Generate a module vulnerability report for a Python file::

            codeaudit modulescan <pythonfile>|<package> [yourreportname.html]

            codeaudit modulescan mypythonfile.py

    Args:
        inputfile (str): Path to a Python source file (*.py) to analyze, or the
            name of a package available on PyPI.
        reportname (str, optional): Name (and optional path) of the HTML file to
            write the vulnerability report to. The filename should use the
            ``.html`` extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

    Returns:
        None: The function writes a static HTML report to disk.

    Raises:
        SystemExit: If the input is not a valid Python file or a valid PyPI
            package. File parsing and I/O errors are reported via standard
            output before exiting.
    """    
    html_output = '<h1>Python Code Audit Report</h1>'    
    file_path = Path(inputfile)
    if file_path.is_dir():
        print("codeaudit modulescan only works on single python files (*.py) or packages present on PyPI.org")
        print("See codeaudit modulescan -h or check the manual https://codeaudit.nocomplexity.com")
        exit(1)        
    elif file_path.suffix == ".py" and file_path.is_file() and is_ast_parsable(inputfile):   
        source = read_in_source_file(inputfile)
        used_modules = get_imported_modules(source)
        # Initial call to print 0% progress
        external_modules = used_modules['imported_modules']    
        l = len(external_modules)
        printProgressBar(0, l, prefix='Progress:', suffix='Complete', length=50)        
        html_output += f'<h2>Module scan report</h2>' 
        html_output += f'<p>Security information for file: <b>{inputfile}</b></p>'
        html_output += f'<p>Total Dependencies Scanned: {l} </p>'
        if external_modules:
            html_output += '<details>' 
            html_output += '<summary>View scanned module dependencies(imported packages).</summary>' 
            html_output += "<ul>\n" + "\n".join(f"  <li>{module}</li>" for module in external_modules) + "\n</ul>"
            html_output += '</details>' 
        else:
            html_output += '<p>&#x2705; No external modules found!' 
        # Now vuln info per external module
        if external_modules:
            html_output += '<h3>Vulnerability information for detected modules</h3>'    
        for i,module in enumerate(external_modules):  #sorted for nicer report
            printProgressBar(i + 1, l, prefix='Progress:', suffix='Complete', length=50)
            html_output += module_vulnerability_check(module) + '<br>'
        html_output += f'<br><p>&#128161; To check for <b>security weaknesses</b> in this package, use the command:<div class="code-box">codeaudit filescan {inputfile}</div><br></p>'
        html_output += '<br>' + DISCLAIMER_TEXT
        create_htmlfile(html_output,reportname)
    elif get_pypi_download_info(inputfile):    
        package_name = inputfile #The input variable  is now equal to the package name         
        html_output += f'<h2>Package scan report for known vulnerabilities</h2>'
        html_output += module_vulnerability_check(package_name)
        html_output += f'<br><p>&#128161; To check for <b>security weaknesses</b> in this package, use the command:<div class="code-box">codeaudit filescan {package_name}</div><br></p>'        
        html_output += '<br>' + DISCLAIMER_TEXT
        create_htmlfile(html_output,reportname)
    else:
        # File is NOT a valid Python file, or package does not exist on PyPI.
        print(f"Error: '{inputfile}' isn't a valid Python file(*.py), or a valid package on PyPI.org.")
        exit(1) 


def module_vulnerability_check(module):
    """
    Build the HTML fragment for the module vulnerability section of a code audit
    module scan report.

    The function checks whether vulnerability information is available for the
    given Python package/module and returns an HTML snippet accordingly:
    - If no vulnerabilities are found, a success message is rendered.
    - If vulnerabilities are found, a collapsible HTML <details> section is
      generated containing the formatted vulnerability data.

    Args:
        module (str): Name of the Python package/module to check.

    Returns:
        str: HTML string representing the vulnerability scan result for the module.
    """   
    output = ""
    vuln_info = check_module_vulnerability(module)
    if not vuln_info:
        # here SAST scan for package? - not needed (now)- do a filescan on Python package manually - dependency trees can be deep and for complex package are never Python only.
        output += f"<p>&#x2705; No known vulnerabilities found for package: <b>{module}</b>.</p>"
    else:
        output += "<details>"
        output += f"<summary>&#9888;&#65039; View vulnerability information for package <b>{module}</b>.</summary>"
        output += json_to_html(vuln_info)
        output += "</details>"
    return output


def collect_issue_lines(filename, line):    
    with open(filename, "r") as f:
        lines = f.readlines()        
    result = [ lines[i - 1] for i in (line -1, line, line + 1)   if i - 1 < len(lines)]
    if result and result[-1] == '\n':        
        result.pop()
    code_lines = '<pre><code class="language-python">' + ''.join(result) + '</code></pre>'
    return code_lines


def create_htmlfile(html_input,outputfile):
    """ Creates a clean html file based on html input given """ 
    # Read CSS from the file - So it is included in the reporting HTML file

    with open(SIMPLE_CSS_FILE, 'r') as css_file:
        css_content = css_file.read()
    # Start building the HTML
    output = '<!DOCTYPE html><html lang="en-US"><head>'
    output += '<meta charset="UTF-8"/>'
    output += '<title>Python_Code_Audit_SecurityReport</title>'
    # Inline CSS inside <style> block
    output += f'<style>\n{css_content}\n</style>'    
    output += '<script src="https://cdn.jsdelivr.net/npm/vega@5"></script>' # needed for altair plots
    output += '<script src="https://cdn.jsdelivr.net/npm/vega-lite@5"></script>' # needed for altair plots
    output += '<script src="https://cdn.jsdelivr.net/npm/vega-embed@6"></script>' # needed for altair plots   
    output += '</head><body>'
    output += '<div class="container">'
    output += html_input
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    code_audit_version = __version__    
    output += (
        f"<p>This Python security report was created on: <b>{timestamp_str}</b> with "
        + PYTHON_CODE_AUDIT_TEXT
        + f" version <b>{code_audit_version}</b></p>"
    )
    output += '<hr>'
    output += '<footer>'    
    output += (
        '<div class="footer-links">'
        'Check the <a href="https://nocomplexity.com/documents/codeaudit/intro.html" '
        'target="_blank">documentation</a> for help on found issues.<br>'
        'Codeaudit is made with <span class="heart">&#10084;</span> by cyber security '
        'professionals who advocate for <a href="https://nocomplexity.com/simplify-security/" target="_blank">open simple security solutions</a>.<br>'
        '<a href="https://nocomplexity.com/documents/codeaudit/CONTRIBUTE.html" target="_blank">Join the community</a> and contribute to make this tool better!'
        "</div>"
    )
    output += "</footer>"
    output += '</div>' #base container
    output += '</body></html>'
    # Now create the HTML output file
    with open(outputfile, 'w') as f:
        f.write(output)    
    current_directory = os.getcwd()
    # Get the directory of the output file (if any)
    directory_for_output = os.path.dirname(os.path.abspath(outputfile))    
    filename_only = os.path.basename(outputfile)
    # Determine the effective directory to use in the file URL
    if not directory_for_output or directory_for_output == current_directory:
        file_url = f'file://{current_directory}/{filename_only}'
    else:
        file_url = f'file://{directory_for_output}/{filename_only}'
    # Print the result
    print("\n=====================================================================")
    print(f'Code Audit report file created!\nPaste the line below directly into your browser bar:\n\t{file_url}\n')
    print("=====================================================================\n")


def extract_altair_html(plot_html):
    match = re.search(r"<body[^>]*>(.*?)</body>", plot_html, re.DOTALL | re.IGNORECASE)
    if match:
        body_content = match.group(1).strip()
        minimal_html = f"{body_content}\n"
        return minimal_html
    else:
        return "<p>Altair plot was supposed to be here: But something went wrong! Fix needed."  # Empty fallback if <body> not found


# Replace the second dot with <br>
def replace_second_dot(s):
    parts = s.split('.')
    if len(parts) > 2:
        return '.'.join(parts[:2]) + '<br>' + '.'.join(parts[2:])
    return s


def get_info_on_test(error):
    """
    Selects row in the checks DataFrame to print help text and severity.

    Args:
        error (str): A string to search for in the ['construct'] column.

    Returns:
        tuple: (severity, info_text)
    """
    severity = 'tbd'
    info_text = 'tbd'
    checks = ast_security_checks()
    df = checks
    # Try to find exact match in 'construct'
    found_rows_exact = df[df['construct'] == error]
    if not found_rows_exact.empty:
        row = found_rows_exact.iloc[0]  # get the first matching row
        severity = row['severity']
        info_text = row['info']
    elif 'extractall' in error:
        # fallback if extractall is mentioned 
        # see also open issues : When both tarfile and zipfile module are used with aliases detection works, but static AST resolution parsing is not 100% possible. Human data flow analyse is needed since aliases can be used. So shortcut taken here, since aliases and usage should be automatic detected!
        fallback_rows = df[df['construct'] == 'tarfile.TarFile']
        if not fallback_rows.empty:
            row = fallback_rows.iloc[0]
            severity = row['severity']
            info_text = row['info']
        else:
            print(f"\nERROR: No fallback row found for 'tarfile.extractall'")
            exit(1)
    else:
        print(f"\nERROR: No row found for '{error}'")
        print(f"No rows found exactly matching '{error}'.")
        exit(1)

    return severity, info_text

def report_implemented_tests(filename=DEFAULT_OUTPUT_FILE):
    """
    Creates an HTML report of all implemented security checks.

    This report provides a user-friendly overview of the static security checks 
    currently supported by Python Code Audit. It is intended to make it easier to review 
    the available validations without digging through the codebase.

    The generated HTML includes:
    - A table of all implemented checks
    - The number of validations
    - The version of Python Code Audit (codeaudit) used
    - A disclaimer about version-specific reporting

    The report is saved to the specified filename and is formatted to be 
    embeddable in larger multi-report documents.

    Help me continue developing Python Code Audit as free and open-source software.
    Join the community to contribute to the most complete, local first , Python Security Static scanner.
    Help!!  Join the journey, check: https://github.com/nocomplexity/codeaudit#contributing 
    

    Parameters:
        filename (str): The output HTML filename. Defaults to 'codeaudit_checks.html'.
    """    
    df_checks = ast_security_checks()
    df_checks['construct'] = df_checks['construct'].apply(replace_second_dot) #Make the validation column smaller - this is the simplest way! without using styling options from Pandas!
    df_checks_sorted = df_checks.sort_values(by='construct')
    output = '<h1>Python Code Audit Implemented validations</h1>' #prepared to be embedded to display multiple reports, so <h2> used
    number_of_test = len(df_checks)
    
    output += df_checks_sorted.to_html(escape=False,index=False)   
    code_audit_version = __version__
    output += '<br>'
    output += f'<p>Number of implemented security validations:<b>{number_of_test}</b></p>'
    output += f'<p>Version of codeaudit: <b>{code_audit_version}</b>'
    output += '<p>Because Python and cybersecurity are constantly changing, issue reports <b>SHOULD</b> specify the codeaudit version used.</p>'
    output += DISCLAIMER_TEXT
    create_htmlfile(output,filename)


def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
        @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)

    """
    if total == 0:
        percent = "100"
        filledLength = 0
        bar = '-' * length
    else:
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)

    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    
    if total != 0 and iteration >= total:
        print()  # New line on completion
