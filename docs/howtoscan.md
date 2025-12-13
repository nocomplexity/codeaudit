# How to do a SAST test?

Running a Static Application Security Test (SAST) on Python code is essential for ensuring security. It’s also a straightforward [shift-left practice](https://nocomplexity.com/documents/simplifysecurity/intro.html#)  that takes only a fraction of your time yet can help you avoid serious security incidents.



Follow these steps to perform a **static application security test (SAST)** on Python projects using **Python Code Audit**.  



## 1. Install Python Code Audit

[Python Code Audit](https://pypi.org/project/codeaudit/) is an open-source, zero-configuration tool that validates whether your Python code introduces potential security vulnerabilities.  

Install (or update) it with:  

```bash
pip install -U codeaudit
```

:::{tip} 
Even if you already have it installed, it’s recommended to run the command again to ensure you’re using the latest checks and features.  
:::



## 2. Clone the Repository you want to scan or use the PyPI package name 

### To scan a directory based on the PyPI package name:

codeaudit filescanscan <package-name-of-package-on-PyPI> [OUTPUTFILE]


### Or clone a repository:  

For direct improvement and inspection of all code using your Python code editor, after examining the Code Audit weakness report:

1. Go to the repository page (e.g., on GitHub).  
2. Click the green **Code** button.  
3. Copy the HTTPS URL.  
4. Run:  

```bash
git clone <repository_url>
```

**Example:** Clone the [Pydantic library](https://github.com/pydantic/pydantic):  

```bash
git clone https://github.com/pydantic/pydantic.git
```

---

## 3. Generate an Overview Report

Navigate into the cloned repository, then run:  

```bash
codeaudit overview
```

This command provides:  
- Total number of files  
- Total lines of code  
- Imported modules  
- Complexity per file  
- Overall complexity score  

:::{tip} 
📖 More detailed explanations of these metrics can be found in the [Python Code Audit documentation](https://nocomplexity.com/documents/codeaudit/intro.html).  
:::



---

## 4. Run a Full Directory Scan

To scan every file in the repository, use:  

```bash
codeaudit filescanscan <DIRECTORY> [OUTPUTFILE]
```

- `DIRECTORY`: Path to the repository folder (e.g., `pydantic`).  
- `OUTPUTFILE` *(optional)*: Name of the HTML report file. If omitted, a default report is created.  

**Example:** Scan the cloned Pydantic package:  

```bash
codeaudit filescan pydantic
```

---

## 5. Review the Security Report

The scan generates a static **HTML report** in the directory where you ran the command.  

Example output path:  

```
file:///home/usainbolt/testdir/codeaudit-report.html
```

- On **Linux**, you can usually click the link directly in the terminal.  
- On **Windows**, you may need to manually copy and paste the file path into your browser.  

---

✅ You now have a detailed static application security test (SAST) report highlighting potential security issues in your Python code. 


:::{hint} 
If you need assistance with solving or want short and clear advice on possible security risks for your context:

Get expert security advice  from one of our [sponsors](sponsors)!

:::