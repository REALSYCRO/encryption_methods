#!/bin/bash


if ! command -v pip &> /dev/null; then
    echo "Pip is not installed. Please install pip."
    exit 1
fi


pip install -r requirements.txt
