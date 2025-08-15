#!/usr/bin/env bash
# split_juliet_train_test.sh
# Randomly split prebuilt Juliet binaries into train/test by CWE.
# Does NOT rebuild. Requires that binaries already exist under $SRC_ROOT/<CWE>/sXX/.
# Each "family" (stem) goes entirely to train or test, and both .unstripped/..out are kept together.

set -euo pipefail

# ---------- CONFIG ----------
export JULIET_ROOT="/mnt/z/juliet/c"
SRC_ROOT="${SRC_ROOT:-$JULIET_ROOT/build}"


DEST_ROOT="${DEST_ROOT:-$JULIET_ROOT/dataset}"

CWES=(
    "CWE78_OS_Command_Injection"
    "CWE190_Integer_Overflow"
    "CWE134_Uncontrolled_Format_String"
    "CWE606_Unchecked_Loop_Condition" 
    "CWE284_Improper_Access_Control" 
    "CWE15_External_Control_of_System_or_Configuration_Setting" 
    "CWE367_TOC_TOU" 
    "CWE325_Missing_Required_Cryptographic_Step"
)


N_TRAIN="${N_TRAIN:-100}"

SEED="${SEED:-42}"

FORCE="${FORCE:-false}"

# ---------- UTILS ----------
have_shuf() { command -v shuf >/dev/null 2>&1; }
rand_shuffle() {
  if have_shuf; then
    SHUF_SEED_OPT=()
    if shuf --help 2>&1 | grep -qi seed; then
      SHUF_SEED_OPT=(--random-source=<(awk "BEGIN{srand($SEED); for(i=0;i<10000;i++) printf(\"%c\", int(rand()*256));}"))
    fi
    shuf "${SHUF_SEED_OPT[@]}" || true
  else
    awk -v seed="$SEED" 'BEGIN{srand(seed)}{printf("%.12f\t%s\n", rand(), $0)}' | sort -k1,1n | cut -f2-
  fi
}

copy_file() {
  local src="$1" dst="$2"
  install -D "$src" "$dst"
}

# ---------- MAIN ----------

if [[ -d "$DEST_ROOT" ]]; then
  if [[ "$FORCE" == "true" ]]; then
    echo "[info] Removing existing DEST_ROOT: $DEST_ROOT"
    rm -rf "$DEST_ROOT"
  else
    echo "[error] DEST_ROOT exists: $DEST_ROOT"
    echo "       Set FORCE=true to overwrite, e.g.: FORCE=true bash $0"
    exit 1
  fi
fi
mkdir -p "$DEST_ROOT/train" "$DEST_ROOT/test"

echo "SRC_ROOT : $SRC_ROOT"
echo "DEST_ROOT: $DEST_ROOT"
echo "CWEs     : ${CWES[*]}"
echo "N_TRAIN  : $N_TRAIN"
echo "SEED     : $SEED"
echo

for CWE in "${CWES[@]}"; do
  src_cwe="$SRC_ROOT/$CWE"
  [[ -d "$src_cwe" ]] || { echo "[warn] missing $src_cwe, skipping $CWE"; continue; }

  echo "==> Processing $CWE"

  mapfile -t files < <(find "$src_cwe" -type f -perm -111 -name "*.unstripped" -o -type f -perm -111 -name "*.out" | sort)
  if ((${#files[@]}==0)); then
    echo "    [warn] no executables under $src_cwe; skipping."
    continue
  fi

  declare -A families=()
  for f in "${files[@]}"; do
    base="$(basename "$f")"
    dir="$(dirname "$f")"
    if [[ "$base" == *.unstripped ]]; then
      stem="${base%.unstripped}"
    elif [[ "$base" == *.out ]]; then
      stem="${base%.out}"
    else
      continue
    fi
    families["$dir/$stem"]=1
  done


  mapfile -t fam_list < <(printf "%s\n" "${!families[@]}" | sort)
  total="${#fam_list[@]}"
  if (( total == 0 )); then
    echo "    [warn] no families found; skipping."
    continue
  fi

  n_pick="$N_TRAIN"
  if (( n_pick > total )); then
    echo "    [note] requested N_TRAIN=$N_TRAIN > total_families=$total; will put ALL in train."
    n_pick="$total"
  fi

  mapfile -t fam_shuffled < <(printf "%s\n" "${fam_list[@]}" | rand_shuffle)
  train_fams=( "${fam_shuffled[@]:0:n_pick}" )
  test_fams=( "${fam_shuffled[@]:n_pick}" )

  echo "    families: total=$total, train=${#train_fams[@]}, test=${#test_fams[@]}"

  train_dbg="$DEST_ROOT/train/$CWE/dbg"
  train_str="$DEST_ROOT/train/$CWE/stripped"
  test_dbg="$DEST_ROOT/test/$CWE/dbg"
  test_str="$DEST_ROOT/test/$CWE/stripped"
  mkdir -p "$train_dbg" "$train_str" "$test_dbg" "$test_str"

  for stem_path in "${train_fams[@]}"; do
    dbg="$stem_path".unstripped
    str="$stem_path".out
    [[ -f "$dbg" ]] && copy_file "$dbg" "$train_dbg/$(basename "$dbg")"
    [[ -f "$str" ]] && copy_file "$str" "$train_str/$(basename "$str")"
  done

  for stem_path in "${test_fams[@]}"; do
    dbg="$stem_path".unstripped
    str="$stem_path".out
    [[ -f "$dbg" ]] && copy_file "$dbg" "$test_dbg/$(basename "$dbg")"
    [[ -f "$str" ]] && copy_file "$str" "$test_str/$(basename "$str")"
  done

  echo "    done $CWE"
done

echo
echo "Split completed."
echo "Train root: $DEST_ROOT/train"
echo "Test  root: $DEST_ROOT/test"
