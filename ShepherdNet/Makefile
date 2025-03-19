.PHONY: build run destroy

build:
	docker build -t frr-modded --no-cache infrastructure-config/frr-modded
	docker-compose build --no-cache
run:
	sudo containerlab deploy --topo infrastructure-config/infra.clab.yml --reconfigure
	sudo containerlab graph --topo infrastructure-config/infra.clab.yml --mermaid
	docker-compose up -d
destroy:
	sudo containerlab destroy --topo infrastructure-config/infra.clab.yml --cleanup
	docker-compose down