#!/bin/sh
# DEVELOPMENT ONLY. Provisions a SoftHSM2 token with a fresh ECDSA P-256 key
# on first start, renders the config with the token's slot id, then runs the
# server. Everything lives under $SOFTHSM_DIR (mount a volume to keep the key
# across restarts; without one a new key, and so a new kid, is made each start).
set -eu

DIR="${SOFTHSM_DIR:-/softhsm}"
TOKEN_LABEL="${SOFTHSM_TOKEN_LABEL:-wallet-as}"
KEY_LABEL="${SOFTHSM_KEY_LABEL:-as-signing}"
SO_PIN="${SOFTHSM_SO_PIN:-5678}"
USER_PIN_FILE="$DIR/user-pin"
USER_PIN="${SOFTHSM_USER_PIN:-1234}"

mkdir -p "$DIR/tokens"
export SOFTHSM2_CONF="$DIR/softhsm2.conf"
cat >"$SOFTHSM2_CONF" <<CONF
directories.tokendir = $DIR/tokens
objectstore.backend = file
log.level = ERROR
CONF

if [ ! -f "$DIR/provisioned" ]; then
    echo "softhsm: initialising token '$TOKEN_LABEL'" >&2
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
        --so-pin "$SO_PIN" --pin "$USER_PIN" >/dev/null
    umask 077
    openssl ecparam -name prime256v1 -genkey -noout \
        | openssl pkcs8 -topk8 -nocrypt -out "$DIR/key.pem"
    softhsm2-util --import "$DIR/key.pem" --token "$TOKEN_LABEL" \
        --label "$KEY_LABEL" --id 01 --pin "$USER_PIN" >/dev/null
    rm -f "$DIR/key.pem"   # the key now lives only in the token
    touch "$DIR/provisioned"
fi
printf '%s' "$USER_PIN" >"$USER_PIN_FILE"

# SoftHSM re-numbers a token's slot when it is initialised, so look it up.
SLOT_ID="$(softhsm2-util --show-slots | awk -v l="$TOKEN_LABEL" '
    /^Slot /{slot=$2} /Label:/{if ($2==l) {print slot; exit}}')"
[ -n "$SLOT_ID" ] || { echo "softhsm: token '$TOKEN_LABEL' not found" >&2; exit 1; }
echo "softhsm: token '$TOKEN_LABEL' is slot $SLOT_ID" >&2

# Render the config: substitute __SOFTHSM_*__ placeholders into a copy.
ARGS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --config)
            src="$2"
            out="$DIR/config.rendered.yaml"
            sed -e "s|__SOFTHSM_SLOT_ID__|$SLOT_ID|g" \
                -e "s|__SOFTHSM_KEY_LABEL__|$KEY_LABEL|g" \
                -e "s|__SOFTHSM_PIN_FILE__|$USER_PIN_FILE|g" \
                -e "s|__SOFTHSM_MODULE__|/usr/lib/softhsm/libsofthsm2.so|g" \
                "$src" >"$out"
            ARGS="$ARGS --config $out"
            shift 2 ;;
        *) ARGS="$ARGS $1"; shift ;;
    esac
done

# shellcheck disable=SC2086
exec /app/server $ARGS
