"""Generate a no-Python POSIX prerequisite entry from a verified release manifest."""
import shlex
from ._bootstrap_manifest import validate,artifact_url

MEMBERS={'macos-arm64':'uv-aarch64-apple-darwin/uv','macos-x86_64':'uv-x86_64-apple-darwin/uv',
         'linux-arm64':'uv-aarch64-unknown-linux-gnu/uv','linux-x86_64':'uv-x86_64-unknown-linux-gnu/uv'}


def posix_script(manifest,manifest_sha256,platform):
    validate(manifest)
    if platform not in MEMBERS or platform not in manifest['prerequisites']['uv']:
        raise ValueError('no pinned POSIX prerequisite for this platform')
    if len(manifest_sha256)!=64 or any(c not in '0123456789abcdef' for c in manifest_sha256):raise ValueError('invalid manifest digest')
    q=shlex.quote;m=manifest;pin=m['prerequisites']['uv'][platform]
    base='"$HOME/Library/Application Support/Capy/Prerequisites"' if platform.startswith('macos') else '"${XDG_DATA_HOME:-$HOME/.local/share}/capy/prerequisites"'
    lines=['#!/bin/sh','set -eu','umask 077','LC_ALL=C; TZ=UTC; export LC_ALL TZ',
      '# Only for a client without compatible Python. Keep native approvals enabled.',
      'client=${1:-muse}','case "$client" in muse|codex) ;; *) exit 2 ;; esac',
      'command -v git >/dev/null || { echo "Native Git prerequisite missing" >&2; exit 1; }',
      'for existing_python in python3 python3.14 python3.13 python3.12 python3.11 python; do',
      'if command -v "$existing_python" >/dev/null 2>&1 && "$existing_python" -I -c "import sys;raise SystemExit(sys.version_info < (3,11))"; then',
      '  echo "Compatible Python is already available; use the ordinary verified installer instructions."','  exit 0','fi','done',
      '[ "$(uname -s):$(uname -m)" = '+q(('Darwin:' if platform.startswith('macos') else 'Linux:')+('arm64' if platform=='macos-arm64' else 'aarch64' if platform=='linux-arm64' else 'x86_64'))+' ] || { echo "This bootstrap script targets another platform" >&2; exit 1; }',
      'command -v curl >/dev/null','command -v tar >/dev/null',
      'command -v '+('lockf' if platform.startswith('macos') else 'flock')+' >/dev/null || { echo "Native file-lock utility missing" >&2; exit 1; }',
      'if command -v shasum >/dev/null; then hash_file() { shasum -a 256 "$1" | cut -d " " -f 1; }; else hash_file() { sha256sum "$1" | cut -d " " -f 1; }; fi',
      'task_base='+base,'task_root="$task_base/'+manifest_sha256+'"',
      'mkdir -p "$task_base"','[ "$(cd "$task_base" && pwd -P)" = "$task_base" ] || { echo "Symlinked prerequisite path refused" >&2; exit 1; }',
      'if [ -e "$task_root" ]; then',
      '  [ ! -L "$task_root" ] && [ -f "$task_root/manifest.sha256" ] && [ "$(cat "$task_root/manifest.sha256")" = '+q(manifest_sha256)+' ] || { echo "Unowned prerequisite directory preserved" >&2; exit 1; }',
      'else mkdir "$task_root"; printf "%s\\n" '+q(manifest_sha256)+' > "$task_root/manifest.sha256"; fi',
      '[ "$('+('stat -f \"%u:%Lp\"' if platform.startswith('macos') else 'stat -c \"%u:%a\"')+' \"$task_root\")" = "$(id -u):700" ] || { echo "Unsafe prerequisite ownership" >&2; exit 1; }',
      '[ ! -L "$task_root/bootstrap.lock" ] || exit 1',
      'exec 9>>"$task_root/bootstrap.lock"',
      '[ -f "$task_root/bootstrap.lock" ] && [ "$('+('stat -f \"%u:%Lp\"' if platform.startswith('macos') else 'stat -c \"%u:%a\"')+' \"$task_root/bootstrap.lock\")" = "$(id -u):600" ] || exit 1',
      ('lockf -t 0 9' if platform.startswith('macos') else 'flock -n 9')+' || { echo "Prerequisite setup is active; retry after it finishes" >&2; exit 1; }',
      'download() {',
      '  target="$task_root/$1"; expected="$2"; size="$3"; url="$4"',
      '  [ ! -L "$target" ] || exit 1',
      '  if [ ! -e "$target" ]; then',
      '    temporary=$(mktemp "$task_root/.download.XXXXXX")',
      '    curl --proto "=https" --tlsv1.2 --fail --silent --show-error --max-redirs 0 --max-filesize "$size" --output "$temporary" "$url"',
      '    [ "$(wc -c < "$temporary" | tr -d " ")" = "$size" ] && [ "$(hash_file "$temporary")" = "$expected" ] || exit 1',
      '    mv "$temporary" "$target"',
      '  fi',
      '  [ "$(wc -c < "$target" | tr -d " ")" = "$size" ] && [ "$(hash_file "$target")" = "$expected" ] || { echo "Changed prerequisite preserved" >&2; exit 1; }','}',
    ]
    for item in (pin['artifact'],pin['downloads'],m['installer']):
        lines.append('download '+' '.join(map(q,[item['filename'],item['sha256'],str(item['size_bytes']),artifact_url(m,item)])))
    uvpath='"$task_root/'+MEMBERS[platform]+'"'
    lines += ['if [ ! -d "$task_root/'+MEMBERS[platform].split('/')[0]+'" ]; then',
      '  tar -xzf "$task_root/'+pin['artifact']['filename']+'" -C "$task_root" '+q(MEMBERS[platform]),'fi',
      '[ ! -L '+uvpath+' ] && [ ! -L "$task_root/'+MEMBERS[platform].split('/')[0]+'" ] || exit 1',
      'expected_uv=$(tar -xOf "$task_root/'+pin['artifact']['filename']+'" '+q(MEMBERS[platform])+' | '+('shasum -a 256' if platform.startswith('macos') else 'sha256sum')+' | cut -d " " -f 1)',
      '[ "$(hash_file '+uvpath+')" = "$expected_uv" ] || { echo "Changed uv preserved" >&2; exit 1; }',
      '# Ignore uv environment overrides; all state remains under this owned directory.',
      'run_uv() { if [ -n "${SSL_CERT_FILE:-}" ]; then env -i PATH="$PATH" HOME="$HOME" SSL_CERT_FILE="$SSL_CERT_FILE" "$@"; else env -i PATH="$PATH" HOME="$HOME" "$@"; fi; }',
      '[ ! -L "$task_root/python.integrity" ] || exit 1',
      'if [ ! -f "$task_root/python.integrity" ]; then',
      '  if [ -e "$task_root/python" ]; then retained=$(mktemp -d "$task_root/interrupted-python.XXXXXX"); mv "$task_root/python" "$retained/python"; fi',
      'run_uv '+uvpath+' --no-config --cache-dir "$task_root/cache" python install --install-dir "$task_root/python" --no-bin --no-registry --python-downloads-json-url "$task_root/'+pin['downloads']['filename']+'" '+q(m['prerequisites']['python_exact']),
    ]
    system='macos' if platform.startswith('macos') else 'linux';arch='aarch64' if platform.endswith('arm64') else 'x86_64';libc='none' if system=='macos' else 'gnu';version=m['prerequisites']['python_exact'];minor='.'.join(version.split('.')[:2])
    python='"$task_root/python/cpython-'+version+'-'+system+'-'+arch+'-'+libc+'/bin/python'+minor+'"'
    managed=python.rsplit('/bin/',1)[0]+'"'
    hasher='shasum -a 256' if platform.startswith('macos') else 'sha256sum'
    inventory=[
      'inventory() {',
      '  destination="$1"; listing=$(mktemp "$task_root/.inventory.XXXXXX")',
      '  find '+managed+' -type f -exec '+hasher+' {} + > "$listing"',
      '  find '+managed+' -type l -exec ls -ldn {} + >> "$listing"',
      '  sort "$listing" > "$destination"; rm -f "$listing"','}']
    # Define the function before the installation branch so replay also uses it.
    offset=lines.index('if [ ! -f "$task_root/python.integrity" ]; then')
    lines[offset:offset]=inventory
    lines += ['  chmod -R a-w '+managed,
      '  initial=$(mktemp "$task_root/.integrity.XXXXXX"); inventory "$initial"',
      '  mv "$initial" "$task_root/python.integrity"',
      'fi',
      '[ ! -L "$task_root/python" ] || exit 1',
      'check=$(mktemp "$task_root/.integrity.XXXXXX"); inventory "$check"',
      'cmp -s "$check" "$task_root/python.integrity" || { echo "Managed Python changed; preserved without execution" >&2; exit 1; }',
      'rm -f "$check"',
      python+' -B -I "$task_root/'+m['installer']['filename']+'" --manifest '+q(m['origin']+'/developer/bootstrap/'+m['release_id']+'/manifest.json')+' --manifest-sha256 '+q(manifest_sha256)+' --client "$client"','']
    return '\n'.join(lines).encode()
