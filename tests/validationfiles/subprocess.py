"""File to check on subprocess usage, which can have severe security risks"""

import subprocess
import os

def run_subprocess_commands_simplified():
    """
    Demonstrates the basic use of subprocess.Popen and subprocess.run to execute shell commands,
    with error handling and try-except blocks removed for simplicity.
    """

    print("--- Using subprocess.run ---")
    print("subprocess.run is a high-level function for simple command execution.")
    print("It waits for the command to complete and returns a CompletedProcess object.")

    # Example 1: Running a simple command and capturing output
    # 'capture_output=True' captures stdout and stderr.
    # 'text=True' decodes stdout/stderr as text (UTF-8 by default).
    # 'check=True' raises a CalledProcessError if the command returns a non-zero exit code (kept for demonstration, but no try-except).
    result_ls = subprocess.run(['ls', '-l'], capture_output=True, text=True, check=True)
    print("\nCommand: ls -l")
    print("Return Code:", result_ls.returncode)
    print("STDOUT:\n", result_ls.stdout)
    print("STDERR:\n", result_ls.stderr)

    # Example 2: Running a command that might fail (to demonstrate 'check=True' without handling)
    # This will raise a CalledProcessError if 'non_existent_command' is not found.
    print("\nCommand: non_existent_command (expected to fail if not found)")
    # subprocess.run(['non_existent_command'], capture_output=True, text=True, check=True)
    # Commented out the failing command to allow the rest of the script to run without interruption
    # if 'non_existent_command' truly doesn't exist.
    # If you uncomment this, be aware it will likely stop execution here with an error.


    print("\n--- Using subprocess.Popen ---")
    print("subprocess.Popen is a lower-level function for more advanced process management.")
    print("It allows for non-blocking execution, piping, and more granular control.")

    # Example 3: Running a command asynchronously with Popen
    # Popen returns a Popen object immediately.
    # We can then interact with the process (e.g., wait, communicate).
    print("\nCommand: echo 'Hello from Popen' && sleep 1 && echo 'Popen finished'")
    # shell=True is used here because '&&' is a shell-specific operator.
    process = subprocess.Popen("echo 'Hello from Popen' && sleep 1 && echo 'Popen finished'",
                               shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True)

    print(f"Popen process started with PID: {process.pid}")
    print("Waiting for Popen process to complete...")

    # communicate() waits for the process to terminate and returns (stdout_data, stderr_data)
    stdout, stderr = process.communicate()

    print("Popen process completed.")
    print("Return Code:", process.returncode)
    print("STDOUT:\n", stdout)
    print("STDERR:\n", stderr)

    # Example 4: Popen with input (piping data to stdin)
    print("\nCommand: grep 'line' (piping input)")
    process_grep = subprocess.Popen(['grep', 'line'],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)

    # Send input to the process's stdin
    input_data = "This is the first line.\nAnd this is the second line.\nNo match here."
    print(f"Sending input to grep:\n{input_data}")
    stdout_grep, stderr_grep = process_grep.communicate(input=input_data)

    print("Return Code:", process_grep.returncode)
    print("STDOUT:\n", stdout_grep)
    print("STDERR:\n", stderr_grep)

    #Old things
    subprocess.check_call(['ls', '-l'])
    return_code = subprocess.call(['ls', '-l'])

# To run the function:
# run_subprocess_commands_simplified()
