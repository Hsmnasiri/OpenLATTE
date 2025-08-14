#!/usr/bin/env bash
# juliet_build_selected.sh
# Build debug + stripped binaries for selected CWEs and all their sXX subfolders.

set -euo pipefail

# ====== CONFIG ======
export JULIET_ROOT="/mnt/z/juliet/c"


CWES=(
    "CWE78_OS_Command_Injection"
    "CWE190_Integer_Overflow"
    "CWE134_Uncontrolled_Format_String"
)

CC=${CC:-gcc}
INCLUDES=(-I"$JULIET_ROOT/testcasesupport")
SUPPORT_SRCS=("$JULIET_ROOT/testcasesupport/io.c" "$JULIET_ROOT/testcasesupport/std_thread.c")

CFLAGS_DEBUG=(-g -O0 -fno-omit-frame-pointer -Wall -Wextra -std=c11)
CFLAGS_REL=(-O2 -DNDEBUG -Wall -Wextra -std=c11)
LDFLAGS=(-pthread)
OUTROOT="$JULIET_ROOT/build"

# ====== FUNCS ======
is_windows_specific() {
  local path="$1"
  [[ "$path" =~ (w32|_w32) ]]
}

compile_family() {
  local cwe_dir="$1"      # e.g., .../testcases/CWE78_OS_Command_Injection/s02
  local stem="$2"         # e.g., CWE78_OS_Command_Injection__char_console_system_54
  local outdir="$3"       # e.g., .../build/CWE78_OS_Command_Injection/s02

  mkdir -p "$outdir"

  local multi_glob="$cwe_dir/${stem}"[a-z].c
  local single_glob="$cwe_dir/${stem}.c"

  local sources=()
  if compgen -G "$multi_glob" >/dev/null; then
    while IFS= read -r -d '' f; do
      is_windows_specific "$f" && continue
      sources+=("$f")
    done < <(find "$cwe_dir" -maxdepth 1 -type f -name "$(basename "$multi_glob")" -print0 | sort -z)
  elif compgen -G "$single_glob" >/dev/null; then
    for f in $single_glob; do
      is_windows_specific "$f" && continue
      sources+=("$f")
    done
  else
    echo "  [skip] no sources for stem $stem"
    return 0
  fi

  if ((${#sources[@]}==0)); then
    echo "  [skip] windows-specific or missing sources for $stem"
    return 0
  fi

  local base="$(basename "$stem")"
  local out_debug="$outdir/${base}.unstripped"
  local out_stripped="$outdir/${base}.out"


  echo "  [CC][dbg] $base"
  "$CC" "${INCLUDES[@]}" -DINCLUDEMAIN "${CFLAGS_DEBUG[@]}" \
    "${SUPPORT_SRCS[@]}" "${sources[@]}" "${LDFLAGS[@]}" -o "$out_debug"

  cp -f "$out_debug" "$out_stripped"
  strip --strip-unneeded "$out_stripped" 2>/dev/null || true

}

discover_and_build_cwe() {
  local cwe="$1"
  local tcase_root="$JULIET_ROOT/testcases/$cwe"
  [[ -d "$tcase_root" ]] || { echo "[warn] not found: $tcase_root"; return; }

  echo "[CWE] $cwe"
  mapfile -t sdirs < <(find "$tcase_root" -mindepth 1 -maxdepth 1 -type d -name "s*" | sort)
  if ((${#sdirs[@]}==0)); then
    sdirs=("$tcase_root")
  fi

  for sdir in "${sdirs[@]}"; do
    local sbase="$(basename "$sdir")"
    local outdir="$OUTROOT/$cwe/$sbase"
    mkdir -p "$outdir"
    echo " [scan] $sdir"

    mapfile -t cfiles < <(find "$sdir" -maxdepth 1 -type f -name "*.c" | sort)
    if ((${#cfiles[@]}==0)); then
      echo "  [skip] no .c files"
      continue
    fi

 
    declare -A stems=()
    for f in "${cfiles[@]}"; do
      is_windows_specific "$f" && continue
      b="$(basename "$f")"
      if [[ "$b" =~ _[0-9]{2}[a-z]\.c$ ]]; then
        stem="${b%[a-z].c}"         
      elif [[ "$b" =~ _[0-9]{2}\.c$ ]]; then
        stem="${b%.c}"               
      else
        continue
      fi
      stems["$stem"]=1
    done

    if ((${#stems[@]}==0)); then
      echo "  [skip] only windows-specific or unmatched files"
      continue
    fi

    for stem in "${!stems[@]}"; do
      compile_family "$sdir" "$stem" "$outdir"
    done
  done
}

# ====== MAIN ======
echo "Juliet root: $JULIET_ROOT"
echo "Output root: $OUTROOT"
mkdir -p "$OUTROOT"

for cwe in "${CWES[@]}"; do
  discover_and_build_cwe "$cwe"
done

echo "Done. Binaries are under: $OUTROOT/<CWE>/sXX/"
