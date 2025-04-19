# Configuration file for Sphinx documentation builder

import sys
import os
from datetime import datetime

# Add project to Python path
sys.path.insert(0, os.path.abspath('../../src'))

# -- Project information -----------------------------------------------------
project = 'AuthNexus'
author = 'Your Name'
copyright = f'{datetime.now().year}, {author}'

# The full version, including alpha/beta/rc tags
release = '0.1.0'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx_rtd_theme',
    'sphinx_copybutton',
    'sphinxcontrib.httpdomain',
    'myst_parser'
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'logo_only': True,
    'navigation_depth': 4,
    'style_external_links': True,
}
html_static_path = ['_static']
html_logo = "_static/logo.png"
html_favicon = "_static/favicon.ico"

# -- Extension settings ------------------------------------------------------
autodoc_default_options = {
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'show-inheritance': True
}

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'cryptography': ('https://cryptography.io/en/latest/', None),
}

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "html_admonition",
]
