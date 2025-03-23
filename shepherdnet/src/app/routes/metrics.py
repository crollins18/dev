from flask import Blueprint, Response, jsonify, request
from requests import get
from ansible_runner import interface
from json import dumps
from time import sleep
from os import getcwd

from core.inspection import routing
from core.inspection import neighbors

metrics_bp = Blueprint('metrics', __name__, url_prefix='/api/v1/getMetric')

restflow_base = "http://clab-fdc-sflow-rt:8008"

def call_restflow(uri_path):
    while True:
        sleep(5)
        response = get(uri_path)
        response_dict = response.json()
        response_str = dumps(response_dict)

        yield f"data: {response_str}\n\n"

@metrics_bp.route('/<string:agent>/<string:metric>', methods=['GET'])
def get_agent_metric(agent, metric):
    endpoint = f"/dump/{agent}/{metric}/json"
    return Response(call_restflow(restflow_base + endpoint), content_type='text/event-stream')

@metrics_bp.route('/<string:agent>/health', methods=['GET'])
def get_agent_health(agent):
    metric = "ifadminstatus"
    endpoint = f"/dump/{agent}/{metric}/json"
    return Response(call_restflow(restflow_base + endpoint), content_type='text/event-stream')

@metrics_bp.route('/<string:agent>/inspect/facts', methods=['GET'])
def get_agent_facts(agent):
    inventory_dict = {
        "frr_devices": {
            "vars": { 
                "ansible_connection": "ansible.netcommon.network_cli",
                "ansible_network_os": "frr.frr.frr",
                "ansible_user": "frruser",
                "ansible_password": "frrpassword",
            },
            "hosts": {
                agent: {
                    "ansible_host": agent,
                }
            },
        },
    }
    r = interface.run(project_dir = getcwd(), playbook="core/inspection/facts.yml", inventory=inventory_dict, extravars={})
    return r.get_fact_cache(agent)

@metrics_bp.route('/<string:agent>/inspect/routing', methods=['GET'])
def get_agent_routes(agent):
    result = routing.get_routing_info(device_type="linux", host=agent, username="frruser", password="frrpassword")
    return result

@metrics_bp.route('/<string:agent>/inspect/neighbors', methods=['GET'])
def get_agent_ip_neighbors(agent):
    result = neighbors.get_ip_neighbor_info(device_type="linux", host=agent, username="frruser", password="frrpassword")
    return result
