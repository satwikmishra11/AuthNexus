#!/bin/bash

echo "Running security checks..."
bandit -r src/
safety check -r requirements/base.txt
trivy fs --severity HIGH,CRITICAL .
