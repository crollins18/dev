from flask import Blueprint, render_template

views_bp = Blueprint("views", __name__)

app_data = {
    "title": "ShepherdNet",
    "description": "A web UI to monitor network status for troubles",
    "author": "Caleb Rollins",
    "topo_filepath": "infra.clab.mermaid",
}

@views_bp.route("/")
def index():
    return render_template("index.html", app_data=app_data)

@views_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", app_data=app_data)

@views_bp.route("/topology")
def topology():
    with open(app_data['topo_filepath'], "r", encoding="utf-8") as f:
        mermaid_code = f.read()
    return render_template("topology.html", app_data=app_data, mermaid_code=mermaid_code)

@views_bp.route("/tickets")
def tickets():
    return render_template("tickets.html", app_data=app_data)