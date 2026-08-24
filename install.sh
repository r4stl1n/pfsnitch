#!/bin/sh
# Install pfsnitch. Run as root, from the repo root.
#
# Deliberately does NOT touch /etc/pf.conf or start anything: this tool sits in
# the packet path, and the last step of installing it should be a decision you
# make while looking at the machine, not a side effect of running a script.
set -eu

PREFIX="${PREFIX:-/usr/local}"
ETCDIR="$PREFIX/etc/pfsnitch"

[ "$(id -u)" = 0 ] || { echo "install.sh: must be root" >&2; exit 1; }
[ -f Cargo.toml ] || { echo "install.sh: run me from the repo root" >&2; exit 1; }

if [ ! -x target/release/pfsnitch ]; then
    echo "install.sh: build first:  cargo build --release" >&2
    exit 1
fi

echo "installing to $PREFIX"

install -d -m 755 "$ETCDIR" "$PREFIX/libexec" "$PREFIX/bin" "$PREFIX/etc/rc.d"
install -m 755 target/release/pfsnitch "$PREFIX/bin/pfsnitch"
install -m 755 bin/pfsnitch-answer     "$PREFIX/bin/pfsnitch-answer"
install -m 755 bin/pfsnitch-panic      "$PREFIX/bin/pfsnitch-panic"

for f in libexec/pfsnitch-*; do
    case "$f" in
        *-common) install -m 644 "$f" "$PREFIX/libexec/$(basename "$f")" ;;
        *)        install -m 755 "$f" "$PREFIX/libexec/$(basename "$f")" ;;
    esac
done

install -m 755 rc.d/pfsnitch "$PREFIX/etc/rc.d/pfsnitch"
install -m 644 etc/anchor.conf   "$ETCDIR/anchor.conf"
install -m 644 etc/failopen.conf "$ETCDIR/failopen.conf"

# Never overwrite a live policy - it is the user's rule set, not ours.
if [ -f "$ETCDIR/policy.conf" ]; then
    echo "  keeping existing $ETCDIR/policy.conf"
else
    install -m 644 etc/policy.conf.sample "$ETCDIR/policy.conf"
    echo "  installed a starter $ETCDIR/policy.conf"
fi

install -d -m 755 /var/run/pfsnitch

cat <<'NEXT'

Installed. Three things left, in this order:

  1. Load the divert module, and at boot:
       kldload ipdivert
       sysrc kld_list+=ipdivert

  2. Add the anchor to /etc/pf.conf. See etc/pf.conf.sample - the key part is
     that outbound is blocked and this anchor re-opens it:

       anchor "pfsnitch"

     Reload with: pfctl -f /etc/pf.conf

  3. Start it in visibility first, and watch what it learns before enforcing:

       sysrc pfsnitch_enable=YES
       service pfsnitch start
       tail -f /var/log/pfsnitch.log

Recovery, if it ever locks you out:  pfsnitch-panic
NEXT
