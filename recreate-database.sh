#!/bin/bash
set -e -v -u;
cat database.txt | sqlite3 users.database;
