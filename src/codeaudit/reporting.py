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

import pandas as pd
import datetime

from codeaudit.security_checks import perform_validations , ast_security_checks
from codeaudit.filehelpfunctions import get_filename_from_path , collect_python_source_files , read_in_source_file 
from codeaudit.altairplots import multi_bar_chart
from codeaudit.totals import get_statistics , overview_count , overview_per_file
from codeaudit.checkmodules import get_imported_modules , check_module_on_vuln , get_all_modules , get_imported_modules_by_file
from codeaudit.htmlhelpfunctions import dict_to_html , json_to_html , dict_list_to_html_table
from codeaudit import __version__

from importlib.resources import files

DISCLAIMER_TEXT = "<p><b>Disclaimer:</b><i>This SAST tool 'codeaudit' provides a powerful automatic security analysis for Python source code. However it's not a substitute for human review in combination with business knowledge. <b>Undetected vulnerabilities may still exist</b>. There is and will never be a single security tool that gives 100% automatic guarantees. By reporting any issues you find, you contribute to a better tool for everyone.</i></p>"


SIMPLE_CSS_FILE = files('codeaudit') / 'simple.css'

DEFAULT_OUTPUT_FILE = 'codeaudit-report.html'

def overview_report(directory, filename=DEFAULT_OUTPUT_FILE):
    """Reports Complexity and statistics per Python file from a directory.
    
    Parameters:
        directory (str): Path to the directory to scan.
        filename (str): Output filename for the HTML report.
    """
    if not os.path.exists(directory):
        print(f"ERROR: Directory '{directory}' does not exist.")
        print(f"This function only works for directories which contains one or more Python source code files (*.py). ")
        exit(1)
    if not os.path.isdir(directory):
        print(f"ERROR: '{directory}' is not a directory (maybe you try to run it for a single file)")
        print(f"This function only works for directories which contains one or more Python source code files (*.py). ")
        exit(1)
    result = get_statistics(directory)    
    df = pd.DataFrame(result)
    overview_df = overview_count(df)
    html = '<h1>' + f'Codeaudit overview report' + '</h1><br>'
    html += f'<p>Codeaudit overview scan of the directory:<b> {directory}</b></p>' 
    html += f'<h2>Summary</h2>'
    html += overview_df.to_html(escape=True,index=False)
    html += '<br><br>'
    security_based_on_max_complexity = overview_df.loc[0,'Maximum_Complexity']
    if security_based_on_max_complexity > 40:        
        html += '<p>Based on the maximum found complexity in a source file: Security concern rate is <b>HIGH</b>'
    else:
        html += '<p>Based on the maximum found complexity in a source file: Security concern rate is <b>LOW</b>'
    security_based_on_loc = overview_df.loc[0,'Number_Of_Lines']
    if security_based_on_loc > 2000:
        html += '<p>Based on the total Lines of Code (LoC) : Security concern rate is <b>HIGH</b>'
    else:
        html += '<p>Based on the total Lines of Code (LoC) : Security concern rate is <b>LOW</b>'
    html += '<br>'
    ## Module overview    
    modules_discovered = get_all_modules(directory)
    html += '<details>' 
    html += '<summary>Click to see all discovered modules.</summary>'         
    html+=dict_to_html(modules_discovered)
    html += '<p><i>The command "codeaudit modulescan" can be used to check if vulnerabilities are reported in an external module.</i></p>' 
    html += '</details>'           
    html += f'<h2>Detailed overview per source file</h2>'
    html += '<details>'     
    html += '<summary>Click to see the report details.</summary>'         
    html += df.to_html(escape=True,index=False)        
    html += '</details>'           
    # I now want only a plot for LoC, so drop other columns from Dataframe
    df = df.drop(columns=['FilePath'])
    plot = multi_bar_chart(df)
    plot_html = plot.to_html()    
    html += '<br><br>'
    html += '<h2>Visual Overview</h2>'    
    html += extract_altair_html(plot_html)    
    create_htmlfile(html,filename)
    

def file_scan_report(file_to_scan , filename=DEFAULT_OUTPUT_FILE):
    """Reports potential security issues for a single Python file.
    
    This function performs security validations on the specified file, 
    formats the results into an HTML report, and writes the output to an HTML file. 
    
    You can specify the name and directory for the generated HTML report.

    Parameters:
        file_to_scan (str)      : The full path to the Python source file to be scanned.
        filename (str, optional): The name of the HTML file to save the report to.
                                  Defaults to `DEFAULT_OUTPUT_FILE`.

    Returns:
        None - A HTML report is written as output
    """
    scan_output = perform_validations(file_to_scan)    
    file_report_html = single_file_report(file_to_scan , scan_output)    
    name_of_file = get_filename_from_path(file_to_scan)
    html = '<h1>Codeaudit report</h1>' #prepared to be embedded to display multiple reports, so <h2> used
    html += f'<h2>Result of scan of file {name_of_file}</h2>'    
    html += '<p>' + f'Location of the file: {file_to_scan} </p>'  
    html += file_report_html    
    html += '<br>'
    html += DISCLAIMER_TEXT
    create_htmlfile(html,filename)  

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
    html = f'<p>Number of potential security issues found: {number_of_issues}</p>'
    html += '<details>' 
    html += '<summary>Click to see the details for found security issues.</summary>'         
    html += df.to_html(escape=False,index=False)        
    html += '</details>'
    file_overview = overview_per_file(filename)    
    df_overview = pd.DataFrame([file_overview])
    html += '<br>'
    html += '<details>' 
    html += f'<summary>Click to see details for file {filename}</summary>'                 
    html += df_overview.to_html(escape=True,index=False)        
    html += '</details>'           
    #imported modules
    html += '<br>'
    html += '<details>' 
    html += '<summary>Click to see details for used modules in this file.</summary>' 
    modules_found = get_imported_modules_by_file(filename)
    html += dict_to_html(modules_found)
    html += f'<p><i>Use the command:<br><b><code>codeaudit modulescan {filename}</code></b><br> to check if vulnerabilities are reported in an external module used by this file.</i></p>' 
    html += '</details>'           
    return html 


def directory_scan_report(directory_to_scan , filename=DEFAULT_OUTPUT_FILE):
    """Reports potential security issues for all Python files found in a directory.
    
    This function performs security validations on all files found in a specified directory.
    The result is written to a HTML report. 
    
    You can specify the name and directory for the generated HTML report.

    Parameters:
        file_to_scan (str)      : The full path to the Python source file to be scanned.
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
    html = '<h1>Codeaudit report</h1>'     
    files_to_check = collect_python_source_files(directory_to_scan)
    html += '<h2>Directory scan report</h2>'     
    html += f'<p>Below the result of the Codeaudit scan of the directory:<b> {directory_to_scan}</b></p>' 
    html += f'<p>Total Python files found: {len(files_to_check)}</p>'
    for file_to_scan in files_to_check:
        scan_output = perform_validations(file_to_scan)
        data = scan_output["result"]
        if data:
            file_report_html = single_file_report(file_to_scan , scan_output)             
            name_of_file = get_filename_from_path(file_to_scan)            
            html += f'<h3>Result for file {name_of_file}</h3>'    
            html += '<p>' + f'Location of the file: {file_to_scan} </p>'          
            html += file_report_html            
        else:
            file_name_with_no_issue = get_filename_from_path(file_to_scan)
            collection_ok_files.append({'filename' : file_name_with_no_issue ,
                                        'directory': file_to_scan})
    html += '<h2>Files in directory with no security issues</h2>'
    html += f'<p>Total Python files with no detected security issue: {len(collection_ok_files)}</p>'
    html += '<p>The Python files with no security issues <b>detected</b> by codeaudit are:<p>'        
    html += dict_list_to_html_table(collection_ok_files)     
    html += '<br>'
    html += '<p><b>Disclaimer:</b><i>Only Python source files are taken into account for this scan. Sometimes security issues are present in configuration files, like ini,yaml or json files!</i></p>'
    html += DISCLAIMER_TEXT
    create_htmlfile(html,filename)  


def report_module_information(inputfile,reportname=DEFAULT_OUTPUT_FILE):
    """Reports module information per file.""" 
    source = read_in_source_file(inputfile)
    used_modules = get_imported_modules(source)
    # Initial call to print 0% progress
    external_modules = used_modules['imported_modules']    
    l = len(external_modules)
    printProgressBar(0, l, prefix='Progress:', suffix='Complete', length=50)    
    html = '<h1>Codeaudit Report</h1>'
    html += f'<h2>Module information for file {inputfile}</h2>'    
    html += dict_to_html(used_modules)    
    #Now vuln info per external module        
    if external_modules:
        html += '<h2>Vulnerability information for detected modules</h2>'    
    for i,module in enumerate(external_modules):  #sorted for nicer report
        printProgressBar(i + 1, l, prefix='Progress:', suffix='Complete', length=50)
        vuln_info = check_module_on_vuln(module)
        if not vuln_info:
            html += f'<h3>Vulnerability information for module <b>{module}</b></h3> '
            html += f'<li>No information found in OSV Database for module: <b>{module}</b>.</li> '
        else:
            html += f'<h3>Vulnerability information for module: <b>{module}</b></h3> '
            html += f'<li>Found vulnerability information in OSV Database for module: <b>{module}</b>:</li>'
            html += json_to_html(vuln_info)    
    create_htmlfile(html,reportname)  


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
    output += '<title>Standard Generated Output File</title>'
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
    output += '<footer>'
    output += '<hr>'
    output += f'<p><small>This security report is created on: {timestamp_str}, with <a href="https://github.com/nocomplexity/codeaudit">codeaudit</a> version {code_audit_version} </small></p>'
    output += '<p><small>Check the <a href="https://nocomplexity.com/documents/codeaudit/intro.html" target="_blank">documentation</a> for help on found issues. <a href="https://github.com/nocomplexity/codeaudit">Codeaudit</a> is made with &#10084; by cyber security professionals who advocate for <a href="https://simplifysecurity.nocomplexity.com" target="_blank">simpler cyber solutions</a> that are transparent and just work. Help to make this FOSS software better!</small></p>'    
    output += '</footer>' 
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
    print(f'Codeaudit report file created!\nPaste the line below directly into your browser bar:\n\t{file_url}\n')
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
    Generate an HTML report of all implemented codeaudit security checks.

    This report provides a user-friendly overview of the static security checks 
    currently supported by codeaudit. It is intended to make it easier to review 
    the available validations without digging through the codebase.

    The generated HTML includes:
    - A table of all implemented checks
    - The number of validations
    - The version of codeaudit used
    - A disclaimer about version-specific reporting

    The report is saved to the specified filename and is formatted to be 
    embeddable in larger multi-report documents.

    Parameters:
        filename (str): The output HTML filename. Defaults to 'codeaudit_checks.html'.
    """    
    df_checks = ast_security_checks()
    df_checks['construct'] = df_checks['construct'].apply(replace_second_dot) #Make the validation column smaller - this is the simplest way! without using styling options from Pandas!
    df_checks_sorted = df_checks.sort_values(by='construct')
    html = '<h1>Codeaudit Implemented validations</h1>' #prepared to be embedded to display multiple reports, so <h2> used
    number_of_test = len(df_checks)
    
    html += df_checks_sorted.to_html(escape=False,index=False)   
    code_audit_version = __version__
    html += '<br>'
    html += f'<p>Number of implemented security validations:<b>{number_of_test}</b></p>'
    html += f'<p>Version of codeaudit: <b>{code_audit_version}</b>'
    html += '<p>Because Python and cybersecurity are constantly changing, issue reports <b>SHOULD</b> specify the codeaudit version used.</p>'
    html += DISCLAIMER_TEXT
    create_htmlfile(html,filename)


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
