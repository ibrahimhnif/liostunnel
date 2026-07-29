.PHONY: up down logs
up:
	./sshd/gen-keys.sh
	./ss/gen-config.sh
	docker compose up -d --build
	@echo "waiting for sshd on 127.0.0.1:22022"
	@for i in $$(seq 1 30); do \
	  nc -z 127.0.0.1 22022 && echo ready && exit 0; sleep 1; done; \
	  echo "sshd did not come up" && exit 1
	@echo "waiting for shadowsocks on 8388 (libev) and 8389 (rust)"
	@for i in $$(seq 1 30); do \
	  nc -z 127.0.0.1 8388 && nc -z 127.0.0.1 8389 && echo ready && exit 0; \
	  sleep 1; done; \
	  echo "a shadowsocks server did not come up" && exit 1
down:
	docker compose down -v
logs:
	docker compose logs -f
