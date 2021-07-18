#!/bin/bash

if [ -d ./dist ]; then
    rm -rf ./dist/*
fi

python3 setup.py bdist_wheel


twine upload dist/*
