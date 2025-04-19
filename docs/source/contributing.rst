Contributing Guide
==================

Development Setup
-----------------
.. code-block:: bash

   git clone https://github.com/yourusername/authnexus.git
   poetry install --all-extras
   pre-commit install

Testing Standards
-----------------
.. code-block:: bash

   pytest --cov=authnexus --cov-report=html
   safety check --full-report
   bandit -r src

Pull Request Checklist
----------------------
1. Unit tests covering new features
2. Documentation updates
3. Type hint coverage
4. Security audit report
5. Performance benchmarks
