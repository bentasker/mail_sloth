#!/bin/sh
# Build and ship to the server.
#   deploy/deploy.sh root@mail.example.com           # build, upload, restart
#   deploy/deploy.sh root@mail.example.com --setup   # first time: also runs setup.sh
set -eu
HOST="${1:?usage: deploy.sh user@host [--setup]}"
MODE="${2:-}"
cd "$(dirname "$0")/.."

deploy/build-linux.sh

if [ "$MODE" = "--setup" ]; then
    ssh "$HOST" 'mkdir -p /root/mail_sloth_setup'
    scp dist/mail_sloth deploy/setup.sh deploy/mail_sloth.service config.example.toml "$HOST":/root/mail_sloth_setup/
    ssh "$HOST" 'cd /root/mail_sloth_setup && sh setup.sh'
    exit 0
fi

scp dist/mail_sloth "$HOST":/usr/local/bin/mail_sloth.new
ssh "$HOST" 'install -m 755 /usr/local/bin/mail_sloth.new /usr/local/bin/mail_sloth \
    && rm /usr/local/bin/mail_sloth.new \
    && systemctl restart mail_sloth \
    && sleep 2 \
    && systemctl --no-pager --lines=5 status mail_sloth'
