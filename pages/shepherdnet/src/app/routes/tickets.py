from flask import Blueprint, Response, jsonify, request
from json import dumps

from app.db import client

tickets_bp = Blueprint('tickets', __name__, url_prefix='/api/v1/tickets')

@tickets_bp.route('/', methods=['GET'])
def get_tkts():
    return client.get_tickets()

@tickets_bp.route('/', methods=['POST'])
def add_tkt():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        
        client.add_ticket(data)

        return jsonify({"message": "Ticket added successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500