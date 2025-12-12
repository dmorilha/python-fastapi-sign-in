#!/bin/bash
set -e -u -v;
sqlite3 'users.database' '.dump';
