#!/bin/bash
for f in /path/to/folder/*.c; do
  make SRC="$f" all
done