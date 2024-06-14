# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import sys
# sys.path.insert(0, os.path.abspath('.'))

import os
import subprocess


# -- Project information -----------------------------------------------------

project = 'HACL Packages'
copyright = '2022, Cryspen'
author = 'Cryspen'

# The full version, including alpha/beta/rc tags
#release = ""


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "myst_parser",
    "breathe",
    "sphinx_multiversion",
    #"sphinx_rtd_theme",
    "sphinx_tabs.tabs",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

html_sidebars = {
    "**": [
        "navbar-logo.html",
        "book.html",
        "search-field.html",
        "sbt-sidebar-nav.html",
        "versioning.html",
    ]
}

html_theme_options = {
    "home_page_in_toc": True
}

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []

source_suffix = {
  '.md': 'markdown',
  '.rst': 'restructuredtext',
}


# -- Options for versioning (sphinx-multiversion) --

# Whitelist pattern for tags (set to None to ignore all tags)
smv_tag_whitelist = r"^c-.*$"

# Whitelist pattern for branches (set to None to ignore all branches)
smv_branch_whitelist = r'^(main)$'

# Whitelist pattern for remotes (set to None to use local branches only)
smv_remote_whitelist = r"^origin$"

# Pattern for released versions
# smv_released_pattern = r'^.*$'

# Format for versioned output directories inside the build directory
smv_outputdir_format = '{ref.name}'

# Determines whether remote or local git branches/tags are preferred if their output dirs conflict
smv_prefer_remote_refs = False


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_book_theme'
#html_theme = 'furo'
#html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Hack ...

if not os.path.exists("../../build"):
    os.mkdir("../../build")

if not os.path.exists("../../build/doxygen"):
    os.mkdir("../../build/doxygen")

subprocess.call(["doxygen"], cwd=os.path.join(os.getcwd(), "../../"))

breathe_projects = {
    "HACL Packages": "../../build/doxygen/xml/",
}

# Breathe Configuration
breathe_default_project = "HACL Packages"

# -- Custom CSS --

# These folders are copied to the documentation's HTML output
html_static_path = ['_static']

# These paths are either relative to html_static_path
# or fully qualified paths (eg. https://...)
html_css_files = [
    'css/custom.css',
]

