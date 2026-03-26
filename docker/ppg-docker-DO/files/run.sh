#!/bin/bash

source validation/bin/activate 
pip install pytest-testinfra psycopg2-binary
pytest test_docker.py -vv -s -rpfs