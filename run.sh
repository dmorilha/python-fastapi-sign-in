#!/bin/bash
set -e -u -v;
source fastapi/bin/activate;
uvicorn main:app --reload;
