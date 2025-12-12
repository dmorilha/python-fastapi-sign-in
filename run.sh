#!/bin/bash
set -e -u -v;
source fastapi/bin/activate >/dev/null 2>&1;
uvicorn main:app --reload;
