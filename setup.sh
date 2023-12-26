#!/bin/bash


if ! command -v pip &> /dev/null; then
    echo "Pip ist nicht installiert. Bitte installiere pip, um fortzufahren."
    exit 1
fi


pip install -r requirements.txt
