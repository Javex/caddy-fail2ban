FROM caddy:2.7-builder AS builder

COPY ./fail2ban.go /src/caddy-fail2ban/
COPY ./go.sum /src/caddy-fail2ban/
COPY ./go.mod /src/caddy-fail2ban/
RUN xcaddy build \
    --with github.com/Javex/caddy-fail2ban=/src/caddy-fail2ban

FROM caddy:2.7

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

RUN apk update && apk add fail2ban curl bash
RUN rm /etc/fail2ban/jail.d/alpine-ssh.conf
COPY ./fail2ban/caddy-banfile.conf /etc/fail2ban/action.d/caddy-banfile.conf
COPY ./test/caddy-test.local /etc/fail2ban/jail.d/caddy-test.local
COPY ./test/caddy-fail2ban-test.sh /usr/local/bin/
RUN chmod u+x /usr/local/bin/caddy-fail2ban-test.sh

