#!/usr/bin/env bash
# Throwaway Shadowsocks credentials for the fixture. Never committed.
#
# Mirrors sshd/gen-keys.sh: generated on first `make up`, reused after, and
# gitignored. A password in the repo is a password in every clone of it.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p conf
chmod 700 conf
# `tr -d` because a trailing newline would become part of the key on one side
# and not the other -- both servers take the password as a literal argument.
[ -f conf/password ] || openssl rand -base64 24 | tr -d '\n' > conf/password
chmod 600 conf/password

# Also written to the compose project's .env, which docker compose reads for
# EVERY command. Passing SS_PASSWORD inline on `up` alone was a trap: any
# later `docker compose up`, `restart` or `ps` run without it interpolates a
# blank password and silently recreates the servers with an empty key -- an
# integration test then fails for a reason that has nothing to do with the
# code under test.
# `umask 077` alone is not enough: `>` truncates an existing file and keeps
# its mode, so a `.env` that was already group- or world-readable stays that
# way and the fixture password with it. The explicit chmod is idempotent, and
# matches the one on conf/password above.
umask 077
printf 'SS_PASSWORD=%s\n' "$(cat conf/password)" > ../.env
chmod 600 ../.env
echo "shadowsocks fixture password ready in $(pwd)/conf/password"
echo "and exported to $(cd .. && pwd)/.env for docker compose"
