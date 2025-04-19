Installation Guide
==================

System Requirements
-------------------
- Python 3.8+
- pip 20.3+
- OpenSSL 1.1.1+

Install from PyPI
----------------
.. code-block:: bash

   pip install authnexus[security]

Development Installation
-------------------------
.. code-block:: bash

   git clone https://github.com/yourusername/authnexus.git
   cd authnexus
   pip install -e .[dev,security]

Verify Installation
-------------------
.. code-block:: bash

   python -c "import authnexus; print(authnexus.__version__)"
