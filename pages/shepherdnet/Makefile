.PHONY: build run destroy test clean

build:
	docker build -t clab-sflow-rt infrastructure-config/clab-sflow-rt
	docker build -t clab-frr infrastructure-config/clab-frr
	docker compose build
run:
	containerlab deploy --topo infrastructure-config/shepherdnet.clab.yml --reconfigure
	containerlab graph --topo infrastructure-config/shepherdnet.clab.yml --mermaid
	docker compose up -d
destroy:
	containerlab destroy --topo infrastructure-config/shepherdnet.clab.yml --cleanup
	docker compose down -v
test:
	test/*.sh
clean:
	docker container prune
	docker image prune
	docker volume prune
	docker network prune
	docker system prune
	docker compose rm -f