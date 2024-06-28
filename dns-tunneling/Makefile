build:
	docker build -t dns-server ./server
	docker build -t workstation ./client
run:
	sudo containerlab deploy --reconfigure
destroy:
	sudo containerlab destroy
	docker ps
force-destroy:
	docker stop $$(docker ps -a -q)
	docker rm $$(docker ps -a -q)
terminal-client:
	docker exec -it clab-dns-tunneling-workstation-1 /bin/bash
terminal-server:
	docker exec -it clab-dns-tunneling-dns-server /bin/bash