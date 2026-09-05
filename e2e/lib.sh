# shellcheck shell=sh
# Shared helpers for the real-driver acceptance scripts, sourced after the
# caller has set $bin (the binary directory). Since M8, opening a grant requires
# an operator approval: `open` records a pending request and returns a
# challenge, and only a verified `approve` runs the drivers. So these tests
# configure an ed25519 approver and drive the open->sign->approve flow rather
# than a bare open.
#
# $bin is referenced here but assigned by the sourcing script.
# shellcheck disable=SC2154

# Generate a throwaway ed25519 approver key at $1 (its public half at $1.pub).
approval_keygen() {
    ssh-keygen -q -t ed25519 -N "" -C "lychgate-approver" -f "$1" </dev/null
}

# Emit an [approval] TOML block trusting the key at $1.pub, for appending to an
# inventory. The full openssh public-key line (with comment) parses; the real
# SSHSIG path proves that in approval-acceptance.sh.
approval_block() {
    printf '\n[approval]\n[[approval.ed25519]]\nkey-id = "acceptance"\npublic-key = "%s"\n' \
        "$(cat "$1.pub")"
}

# open_and_approve <socket> <host> <ttl> <approver_key>
# Open a grant, sign the returned challenge with the approver key, and approve
# it — the same round trip an operator performs. Only the approve's stdout (the
# now-open grant, its shown-once secret and endpoint) reaches the caller's
# stdout; the challenge is consumed internally. Returns non-zero if either the
# open or the approve is refused, so callers can guard with `if`.
open_and_approve() {
    _oa_sock="$1"
    _oa_host="$2"
    _oa_ttl="$3"
    _oa_key="$4"
    _oa_challenge="$(
        "${bin}/lychgate" --socket "${_oa_sock}" open --host "${_oa_host}" --ttl "${_oa_ttl}" \
            | sed -n 's/^challenge: //p'
    )"
    [ -n "${_oa_challenge}" ] || return 1
    printf '%s' "${_oa_challenge}" \
        | ssh-keygen -Y sign -n lychgate-approval -f "${_oa_key}" 2>/dev/null \
        | "${bin}/lychgate" --socket "${_oa_sock}" approve --host "${_oa_host}"
}
