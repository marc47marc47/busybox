#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

case "$(uname -s)" in
	CYGWIN*|MSYS*|MINGW*) ;;
	*)
		echo "init-env.sh: run this script in an MSYS2 or Git for Windows SDK shell" >&2
		exit 1
		;;
esac

if ! command -v pacman >/dev/null 2>&1; then
	cat >&2 <<'EOF'
init-env.sh: pacman was not found.

Install MSYS2 or Git for Windows SDK, open its shell, and run this script
again.  A regular Git Bash installation does not include the C compiler
needed to build BusyBox.
EOF
	exit 1
fi

echo "Installing BusyBox build dependencies..."
pacman -S --needed --noconfirm \
	binutils \
	diffutils \
	gcc \
	make \
	perl

# shellcheck source=setenv.busybox
source "$script_dir/setenv.busybox"

echo
echo "Build dependencies are ready."
echo "Run: source setenv.busybox"
echo "Then: ./build.sh"
