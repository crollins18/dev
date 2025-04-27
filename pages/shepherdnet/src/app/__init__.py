from flask import Flask
from .routes.views import views_bp
from .routes.metrics import metrics_bp
from .routes.tickets import tickets_bp

def create_app():
    app = Flask(__name__)
    app.register_blueprint(views_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(tickets_bp)
    return app