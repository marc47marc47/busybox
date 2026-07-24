#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir"

# Keep the Windows build environment in one place.  This also makes sure that
# an unrelated Windows make.exe (for example, one from an embedded toolchain)
# is not selected before the MSYS/Cygwin build tools.
# shellcheck source=setenv.busybox
source "$script_dir/setenv.busybox"

usage()
{
	cat <<'EOF'
Usage: ./build.sh [options]

Options:
  -c, --clean          Remove previous build output before building
  -r, --reconfigure    Restore configs/cygwin_defconfig before building
  -j, --jobs N         Run N parallel build jobs
  -h, --help           Show this help

The first build automatically uses configs/cygwin_defconfig.  Later builds
preserve the existing .config unless --reconfigure is specified.
EOF
}

clean=0
reconfigure=0
jobs=${BUSYBOX_BUILD_JOBS:-}

while (($#)); do
	case "$1" in
		-c|--clean)
			clean=1
			;;
		-r|--reconfigure)
			reconfigure=1
			;;
		-j|--jobs)
			[[ $# -ge 2 ]] || {
				echo "build.sh: --jobs requires a number" >&2
				exit 2
			}
			jobs=$2
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "build.sh: unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
	shift
done

[[ ${jobs:-} =~ ^[1-9][0-9]*$ ]] || {
	echo "build.sh: job count must be a positive integer" >&2
	exit 2
}

required_tools=(awk gcc make perl sed)
missing_tools=()
for tool in "${required_tools[@]}"; do
	command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
done

if ((${#missing_tools[@]})); then
	echo "build.sh: missing build tools: ${missing_tools[*]}" >&2
	echo "Run ./init-env.sh first." >&2
	exit 1
fi

case "$(uname -s)" in
	CYGWIN*|MSYS*|MINGW*) ;;
	*)
		echo "build.sh: this script must run in an MSYS2, Git SDK, or Cygwin shell" >&2
		exit 1
		;;
esac

if ((clean)); then
	make clean
fi

if ((reconfigure)) || [[ ! -f .config ]]; then
	echo "Configuring BusyBox for Windows (Cygwin/MSYS)..."
	cp configs/cygwin_defconfig .config
	sed -i \
		-e 's/^CONFIG_EXTRA_LDLIBS=""$/CONFIG_EXTRA_LDLIBS="ntdll"/' \
		.config

	# These Linux-only applets require kernel headers which are deliberately
	# absent from the Windows POSIX environments.
	for option in \
		HALT POWEROFF REBOOT RUN_INIT \
		NSENTER LINUX32 LINUX64 SETPRIV \
		FEATURE_SETPRIV_CAPABILITIES FEATURE_SETPRIV_CAPABILITY_NAMES \
		FEATURE_USE_SENDFILE FEATURE_SYNC_FANCY CHRT \
		SHA1_HWACCEL SHA256_HWACCEL \
		I2CGET I2CSET I2CDUMP I2CDETECT I2CTRANSFER \
		PARTPROBE SEEDRNG BLKDISCARD MKE2FS FSTRIM FSFREEZE MKDOSFS \
		SWAPON SWAPOFF UNSHARE UBIRENAME UEVENT UDHCPC6 \
		IPNEIGH FEATURE_IP_NEIGH
	do
		sed -i \
			-e "s/^CONFIG_${option}=y$/# CONFIG_${option} is not set/" \
			.config
	done

	# The checked-in defconfig can predate newly added options.  Accept each
	# new option's Kconfig default without requiring an interactive terminal.
	# BusyBox's Kconfig parser requires blank lines inside help blocks to retain
	# indentation.  This matters on the native Windows/MSYS host build, where
	# otherwise the continuation paragraphs are reported as unknown options.
	while IFS= read -r -d '' config_in; do
		sed -i 's/^$/\t/' "$config_in"
	done < <(find . -name Config.in -print0)
	set +o pipefail
	yes "" | make oldconfig >/dev/null
	config_status=${PIPESTATUS[1]}
	set -o pipefail
	((config_status == 0)) || exit "$config_status"
fi

echo "Building BusyBox with $jobs parallel jobs..."
if [[ $(uname -s) == CYGWIN* || $(uname -s) == MSYS* || $(uname -s) == MINGW* ]]; then
	make -j"$jobs" TC_WINDOWS=y
else
	make -j"$jobs"
fi

if [[ ! -x busybox ]]; then
	echo "build.sh: build completed but no BusyBox executable was found" >&2
	exit 1
fi

if [[ ! -x busybox.exe ]]; then
	cp -f busybox busybox.exe
fi
output=busybox.exe

echo "Build complete: $script_dir/$output"
