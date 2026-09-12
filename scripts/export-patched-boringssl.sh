#!/usr/bin/env bash
# Re-export the boringssl conan recipe from a newer NativeLibsCommon on top of
# the one the upstream bootstrap exported from the pinned NLC.
#
# Upstream (v1.1.5) pins native_libs_common/8.1.49, whose make_ssl.cpp calls
# SSL_set_server_padding_request, SSL_set_grease_sigalgs_enabled and
# SSL_set_extension_order. Those are declared only by NLC's 21_extension_order
# and 22_chrome_canary_extensions patches, first shipped in v8.1.47. AdGuard's
# own CI resolves a fresher recipe REVISION of openssl/boring-2024-09-13 from
# their internal conan remote; building from plain git we must re-export that
# recipe ourselves. Same package name/version, later export timestamp — conan
# picks this revision over the bootstrap's one.
#
# This pin must therefore track upstream's, not lead it: an older re-export
# wins on timestamp and silently downgrades the recipe out from under the NLC
# upstream actually asked for, which fails to compile rather than fails safe.
#
# Supply chain: this recipe is Python that runs at export/build time and it
# picks the boringssl source that every shipped VPN binary links statically, so
# it is pinned twice — to the immutable commit behind the v8.1.45 tag (tags can
# be moved), and to a SHA-256 over the exported recipe tree (a rewritten commit
# or a tampered mirror then fails the build instead of quietly swapping our TLS
# stack). Bumping NLC means updating BOTH constants below; re-run with
# FT_PRINT_RECIPE_DIGEST=1 to print the new digest. scripts/check-pinned-deps.sh
# keeps them from degrading back into a movable ref.
set -euo pipefail

# NativeLibsCommon v8.1.49 — annotated tag v8.1.49 peeled to its commit
# (git ls-remote https://github.com/AdguardTeam/NativeLibsCommon 'v8.1.49^{}').
NLC_COMMIT="fd7405ee27fe040fffa094782fd4e9c5ea35fa34"
# Digest of conan/recipes/boringssl at that commit (see recipe_digest below).
NLC_RECIPE_SHA256="1908518580b6c925b0afb1cb7bfbdb194255b1841afd74844a83e1fe4a7a1dc6"
NLC_URL="https://github.com/AdguardTeam/NativeLibsCommon.git"

# macOS runners have shasum, Linux/git-bash have sha256sum.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
  else
    shasum -a 256
  fi
}

# Stable digest of a directory tree: one "<file sha256>  <relative path>" line
# per file, byte-sorted, hashed again. The checkout below forces LF so the
# digest also matches on the Windows runner.
recipe_digest() {
  # Without this, a moved/renamed recipe path makes `cd` fail, the subshell then
  # hashes the CALLER's working directory, and the mismatch reads as "someone
  # tampered with the recipe" instead of "the path is wrong".
  if [[ ! -d "$1" ]]; then
    echo "boringssl: recipe directory not found: $1" >&2
    exit 1
  fi
  (
    cd "$1"
    find . -type f | LC_ALL=C sort | while IFS= read -r f; do
      printf '%s  %s\n' "$(sha256 < "$f" | cut -d' ' -f1)" "$f"
    done
  ) | sha256 | cut -d' ' -f1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Fetch the pinned commit itself — never a branch or tag, which can be repointed.
git init -q "$TMP/nlc"
git -C "$TMP/nlc" config core.autocrlf false
git -C "$TMP/nlc" config core.eol lf
git -C "$TMP/nlc" remote add origin "$NLC_URL"
git -C "$TMP/nlc" fetch -q --depth 1 origin "$NLC_COMMIT"
git -C "$TMP/nlc" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD

head="$(git -C "$TMP/nlc" rev-parse HEAD)"
if [[ "$head" != "$NLC_COMMIT" ]]; then
  echo "boringssl: NLC checkout is $head, expected $NLC_COMMIT" >&2
  exit 1
fi

RECIPE="$TMP/nlc/conan/recipes/boringssl"
digest="$(recipe_digest "$RECIPE")"
if [[ "${FT_PRINT_RECIPE_DIGEST:-0}" == "1" ]]; then
  echo "boringssl recipe digest: $digest"
fi
if [[ "$digest" != "$NLC_RECIPE_SHA256" ]]; then
  echo "boringssl: recipe tree digest mismatch at ${NLC_COMMIT}" >&2
  echo "  expected $NLC_RECIPE_SHA256" >&2
  echo "  actual   $digest" >&2
  exit 1
fi

conan export "$RECIPE" --user adguard --channel oss
echo "boringssl recipe exported from NLC ${NLC_COMMIT} (recipe ${digest})"
