set -euo pipefail

# point the makefile at your Juliet source tree
export JULIET_ROOT="/mnt/z/juliet/c"

for d in "${JULIET_ROOT}"/testcases/CWE78_OS_Command_Injection/s*; do
  for src in "$d"/*.c; do
    echo "▶ Compiling $src"
    make -f Juliet.mk SRC="$src" all
  done
done