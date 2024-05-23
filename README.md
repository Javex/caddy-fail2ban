# caddy-fail2ban

A simple package to add [fail2ban](https://github.com/fail2ban/fail2ban) support to [caddy](https://caddyserver.com/). This simple module adds a `fail2ban` HTTP matcher based on a text file of IP addresses.

## Getting Started

First, make sure to build your caddy with support for this module:

```bash
RUN xcaddy build \
    --with github.com/Javex/caddy-fail2ban@main
```

Then insert this into your `Caddyfile`:

```Caddyfile
@banned {
	fail2ban ./banned-ips
}
handle @banned {
	abort
}
```

The right place for it depends on your setup, but you can find more complete examples in the [examples/](examples/) directory.

Next, you will need to create the fail2ban action. You can copy the suggested one if you like:

```bash
$ cp fail2ban/caddy-banfile.conf /etc/fail2ban/actions.d/caddy-banfile.conf
```

Now in any of your jails if you want to block requests at the HTTP layer, you can use the action:

```ini
action = caddy-banfile[banfile_path="/etc/caddy/banned-ips"]
```

The above path is the default so you can omit the `banfile_path` parameter if you like.

## Running tests

First run the go unit tests, then spin up a docker container to test the
integration with fail2ban

```
go build -v ./...
go test -v ./...

sudo docker build . -t caddy-fail2ban
sudo docker run --rm --name caddy-fail2ban --detach -v $PWD/test/Caddyfile:/etc/caddy/Caddyfile caddy-fail2ban
sudo docker exec -it caddy-fail2ban /usr/local/bin/caddy-fail2ban-test.sh
sudo docker logs caddy-fail2ban
sudo docker stop caddy-fail2ban
```
