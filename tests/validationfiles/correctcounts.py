#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Copyright (C) 2019 - Maikel Mardjan - info_at_nocomplexity_dot_com
All code is GPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import fire
import os
import nbformat as nbf


def base_project_info():
    projectname = input("Enter projectname:")
    projectauthor = input("Enter your name:")
    projectdirectory = input("Enter projectdirectory:")
    project_info = [projectname, projectauthor, projectdirectory]
    return project_info


def create_directory(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print("Created directory: " + directory)
    except OSError:
        print("Error: Creating directory. " + directory)


def create_new_sphinx_project(projectname, author, projectdir):
    import subprocess
    import os

    os.chdir(projectdir)  # Note: Directory MUST be empty!
    cmd = subprocess.run(
        [
            "sphinx-quickstart",
            "--quiet",
            "-p mmtest",
            "-v 0.0.1",
            "-a Mike",
            "--sep",
            "--ext-githubpages",
        ],
        stdout=subprocess.PIPE,
    )
    return cmd


def generate_notebook_with_toc(toc_chapters, projectname):
    nb = nbf.v4.new_notebook()
    nb["cells"] = [nbf.v4.new_markdown_cell("# " + toc_chapters[0] + "\n")]
    for section in toc_chapters:
        nb["cells"].append(nbf.v4.new_markdown_cell("## " + section + "\n"))
    nbf.write(nb, projectname + ".ipynb")
    return


def generate_notebook_design_template(markdown_template_file, projectname):
    # reads a markdown file and turn it into a notebook with seperate cells per section
    filename = markdown_template_file
    nb = nbf.v4.new_notebook()
    nb["cells"] = [nbf.v4.new_markdown_cell("# " + "Generated notebook a md template")]
    with open(filename, "r") as f:
        feedfile = f.readlines()  # import the file as Python dict
    # now feedfile contains the input of the md file , separated per line
    # So now Loop through the file line by line and if first line starts with # than new cell
    cell_content = ""
    for cell in feedfile:
        newcell = cell.startswith("#")
        if newcell:
            nb["cells"].append(nbf.v4.new_markdown_cell(cell_content))
            nb["cells"].append(nbf.v4.new_markdown_cell(cell))
            cell_content = ""
        else:
            cell_content += cell
    nbf.write(nb, projectname + ".ipynb")
    print("Your notebook for working on: {} is created".format(markdown_template_file))
    return


def get_commiters_list_of_gitrepro(directory):
    """
    retrieves number of commiters and number of commits per author
    note: no author emails
    else do: git shortlog --summary --numbered --email
    now command used is:  git shortlog --summary --numbered
    It works, but NOT in notebook, due to stdout redirecting issue(goes in zmq pipe)
    """
    import subprocess
    import os

    os.chdir(directory)  # Note: Directory MUST be empty!
    cmd = subprocess.run(
        ["git", "shortlog", "--summary", "--numbered"], stdout=subprocess.PIPE
    )
    output = cmd.stdout.decode("utf-8")
    print(output)
    return output


if __name__ == "__main__":
    fire.Fire()
