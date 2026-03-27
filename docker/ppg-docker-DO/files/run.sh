#!/bin/bash

source validation/bin/activate
pip install --upgrade pip
pip install psycopg2-binary
pip install pytest-testinfra
pytest test_docker.py -vv -s -rpfs