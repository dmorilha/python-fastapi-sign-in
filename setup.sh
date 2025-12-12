#!/bin/bash
set -e -u -v;
python3.13 -m venv fastapi;
source fastapi/bin/activate;
pip install -r requirements.txt;
