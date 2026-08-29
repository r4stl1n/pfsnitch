#!/bin/sh
# install.sh - one-command installer for pfsnitch.
#
# Builds it, installs it, wires it to start at boot, and - only after you say so
# - arms it. The parts that touch the packet path (editing /etc/pf.conf, turning
# pf on, starting the firewall) come last and are done in the one ordering that
# cannot strand the machine: the daemon starts FIRST, in visibility mode (every
# packet is reinjected, nothing is blocked), and only then is pf pointed at it.
# Inbound SSH and DHCP stay open throughout, so a remote box is never locked out.
#
#   ./install.sh            build + install, then ask before touching the network
#   ./install.sh --yes      ... and arm without asking (for automation)
#   ./install.sh --no-arm   build + install only; leave pf and startup to you
set -eu

PREFIX="${PREFIX:-/usr/local}"
ETCDIR="$PREFIX/etc/pfsnitch"
ASSUME_YES=0
DO_ARM=1

for a in "$@"; do
    case "$a" in
        --yes|-y)  ASSUME_YES=1 ;;
        --no-arm)  DO_ARM=0 ;;
        -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "install.sh: unknown option $a (try --help)" >&2; exit 2 ;;
    esac
done

say()  { printf '\n\033[1m==>\033[0m %s\n' "$1"; }
info() { printf '    %s\n' "$1"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$1" >&2; }
die()  { printf '\033[31minstall.sh: %s\033[0m\n' "$1" >&2; exit 1; }
ask()  {   # ask "question" default(y|n) -> 0 for yes
    [ "$ASSUME_YES" = 1 ] && return 0
    printf '    %s [%s] ' "$1" "$2"
    read -r ans || ans=""
    case "${ans:-$2}" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
sysrc_add() {   # idempotently append a word to an rc.conf list variable
    sysrc -n "$1" 2>/dev/null | grep -qw "$2" || sysrc "$1+=$2" >/dev/null 2>&1 || true
}

manual_arm() {
    EXT_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
    cat <<MANUAL
    Everything is installed and set to start at boot. To arm it by hand:

      1. Start it (daemon first, in visibility - nothing is blocked yet):
           service pfsnitch start

      2. Point pf at it. Edit /etc/pf.conf per etc/pf.conf.sample - set
         ext_if to "${EXT_IF:-your external interface}" and add:  anchor "pfsnitch"
         then:  pfctl -f /etc/pf.conf

      3. Watch what it learns, then when the rules look right:
           pfsnitch apps
           pfsnitch mode enforcement

    Recovery if it ever locks you out:  pfsnitch-panic
MANUAL
}

# --- preflight -------------------------------------------------------------
[ "$(id -u)" = 0 ]          || die "must be run as root (try: doas ./install.sh)"
[ "$(uname -s)" = FreeBSD ] || die "pfsnitch is FreeBSD-only (this is $(uname -s))"
[ -f Cargo.toml ]           || die "run me from the repo root"
command -v pfctl >/dev/null 2>&1 || die "pfctl not found - pf(4) is required"

# --- build the daemon ------------------------------------------------------
say "Building the daemon"
if command -v cargo >/dev/null 2>&1; then
    cargo build --release || die "cargo build failed"
elif [ -x target/release/pfsnitch ]; then
    info "cargo not found, but target/release/pfsnitch already exists - using it"
else
    die "cargo not found and nothing prebuilt. Install Rust:  pkg install rust"
fi
[ -x target/release/pfsnitch ] || die "build produced no target/release/pfsnitch"
info "built target/release/pfsnitch"

# --- build the kernel module (optional) ------------------------------------
say "Kernel attribution module (optional - the userspace path works without it)"
KMOD=0
if [ -f kmod/mac_pfsnitch.ko ]; then
    info "already built."; KMOD=1
elif [ -d /usr/src/sys ] && command -v make >/dev/null 2>&1; then
    if ( cd kmod && make ) >/tmp/pfsnitch-kmod-build.log 2>&1; then
        info "built kmod/mac_pfsnitch.ko"; KMOD=1
    else
        warn "module build failed (see /tmp/pfsnitch-kmod-build.log) - continuing without it"
    fi
else
    info "no kernel sources at /usr/src - skipping the module."
fi

# --- install files ---------------------------------------------------------
say "Installing to $PREFIX"
install -d -m 755 "$ETCDIR" "$PREFIX/libexec" "$PREFIX/bin" "$PREFIX/etc/rc.d" /var/run/pfsnitch
install -m 755 target/release/pfsnitch "$PREFIX/bin/pfsnitch"
install -m 755 bin/pfsnitch-answer     "$PREFIX/bin/pfsnitch-answer"
install -m 755 bin/pfsnitch-panic      "$PREFIX/bin/pfsnitch-panic"
for f in libexec/pfsnitch-*; do
    case "$f" in
        *-common) install -m 644 "$f" "$PREFIX/libexec/$(basename "$f")" ;;
        *)        install -m 755 "$f" "$PREFIX/libexec/$(basename "$f")" ;;
    esac
done
install -m 755 rc.d/pfsnitch      "$PREFIX/etc/rc.d/pfsnitch"
install -m 644 etc/anchor.conf    "$ETCDIR/anchor.conf"
install -m 644 etc/udpdivert.conf "$ETCDIR/udpdivert.conf"
install -m 644 etc/failopen.conf  "$ETCDIR/failopen.conf"
if [ -f "$ETCDIR/policy.conf" ]; then
    info "keeping your existing policy.conf (your rules are never overwritten)"
else
    install -m 644 etc/policy.conf.sample "$ETCDIR/policy.conf"
    info "installed a starter policy.conf"
fi
if [ "$KMOD" = 1 ]; then
    install -d -m 755 /boot/modules
    install -m 555 kmod/mac_pfsnitch.ko /boot/modules/mac_pfsnitch.ko
    info "installed /boot/modules/mac_pfsnitch.ko"
fi

# --- boot wiring (safe: touches no live traffic) ---------------------------
say "Wiring it up to start at boot"
kldload ipdivert 2>/dev/null || true
sysrc_add kld_list ipdivert
info "ipdivert loaded and set to load at boot"
if [ "$KMOD" = 1 ]; then
    if kldstat -q -m mac_pfsnitch || kldload mac_pfsnitch 2>/dev/null; then
        sysrc_add kld_list mac_pfsnitch
        grep -q '^attribution' "$ETCDIR/policy.conf" 2>/dev/null || \
            printf 'attribution kernel\n' >> "$ETCDIR/policy.conf"
        info "mac_pfsnitch loaded, set to load at boot, and selected (attribution kernel)"
    else
        warn "the module built but will not load (kernel version mismatch?) - using the userspace path"
    fi
fi
sysrc pfsnitch_enable=YES     >/dev/null 2>&1 || true
sysrc pfsnitch_mode=visibility >/dev/null 2>&1 || true
info "pfsnitch enabled at boot, starting mode VISIBILITY (learns, never blocks)"

# --- arm: pf + start (the one part that touches the network) ---------------
if [ "$DO_ARM" = 0 ]; then
    say "Installed. Not arming (--no-arm)."
    manual_arm
    exit 0
fi

say "Arm it now?  This is the only step that touches live traffic."
EXT_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
info "It will, in the one order that cannot strand the box:"
info "  1. start the daemon in visibility - every packet reinjected, nothing blocked"
info "  2. point /etc/pf.conf at it (external interface detected: ${EXT_IF:-UNKNOWN})"
info "Inbound SSH and DHCP stay open; a crash fails open via the watchdog."
[ -z "${EXT_IF:-}" ] && warn "could not detect your external interface - you may need to set ext_if by hand"
if ! ask "Proceed with arming?" y; then
    say "Left unarmed. Everything is installed; arm it when you're ready:"
    manual_arm
    exit 0
fi

# 1. daemon first
service pfsnitch start || die "daemon failed to start - NOT touching /etc/pf.conf"

# 2. pf.conf - carefully
if { [ -f /etc/pf.conf ] && grep -q 'anchor "pfsnitch"' /etc/pf.conf; }; then
    info "/etc/pf.conf already references the pfsnitch anchor - loading it"
    pfctl -f /etc/pf.conf 2>/dev/null || warn "pfctl -f /etc/pf.conf reported errors - check it"
    pfctl -e 2>/dev/null || true
elif [ ! -f /etc/pf.conf ] || ! grep -qE '^[[:space:]]*[^#[:space:]]' /etc/pf.conf; then
    # no pf.conf, or one that is entirely comments/blank: install the sample
    [ -f /etc/pf.conf ] && cp /etc/pf.conf "/etc/pf.conf.pre-pfsnitch.$(date +%s)"
    IF="${EXT_IF:-em0}"
    sed "s/ext_if = \"em0\"/ext_if = \"$IF\"/" etc/pf.conf.sample > /etc/pf.conf.pfsnitch.new
    if pfctl -nf /etc/pf.conf.pfsnitch.new >/dev/null 2>&1; then
        mv /etc/pf.conf.pfsnitch.new /etc/pf.conf
        pfctl -ef /etc/pf.conf 2>/dev/null || pfctl -f /etc/pf.conf
        info "installed /etc/pf.conf for interface '$IF' and enabled pf"
        [ -z "${EXT_IF:-}" ] && warn "guessed ext_if=em0 - edit /etc/pf.conf if that is wrong, then: pfctl -f /etc/pf.conf"
    else
        rm -f /etc/pf.conf.pfsnitch.new
        warn "the generated pf.conf did not validate (bad interface?) - pf left untouched. See etc/pf.conf.sample."
    fi
else
    warn "you already have a custom /etc/pf.conf - not editing it automatically."
    info "Add these lines yourself (see etc/pf.conf.sample for the full context):"
    info "    block out all"
    info "    anchor \"pfsnitch\""
    info "  keep an inbound SSH pass rule, then:  pfctl -f /etc/pf.conf"
fi

# --- done ------------------------------------------------------------------
say "Done - pfsnitch is running in visibility mode"
cat <<DONE
    It is watching and learning now, blocking nothing. When you are ready:

      pfsnitch apps                 review what it has learned, per application
      pfsnitch mode enforcement     start prompting for anything new, dropping the rest

    Recovery if it ever locks you out:  pfsnitch-panic
DONE
