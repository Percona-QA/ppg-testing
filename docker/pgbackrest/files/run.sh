#!/bin/bash

source validation/bin/activate
pip install pytest-testinfra
pytest test_docker.py -vv -s -rpfs