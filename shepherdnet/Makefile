.PHONY: build run destroy

build:
	docker build -t clab-sflow-rt infrastructure-config/clab-sflow-rt
	docker build -t clab-frr infrastructure-config/clab-frr
	docker compose build
run:
	sudo containerlab deploy --topo infrastructure-config/bgp-frr.clab.yml
	sudo containerlab graph --topo infrastructure-config/bgp-frr.clab.yml --mermaid
	docker compose up -d
destroy:
	sudo containerlab destroy --topo infrastructure-config/bgp-frr.clab.yml --cleanup
	docker compose down