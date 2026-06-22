# app.py

from flask import Flask, render_template, jsonify
import detector
from database import (
    initialize_database,
    get_all_alerts,
    clear_all_alerts,
    resolve_alert
)

app = Flask(__name__)

initialize_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/start", methods=["POST"])
def start_monitoring():
    return jsonify({
        "message": detector.start_monitoring()
    })


@app.route("/api/stop", methods=["POST"])
def stop_monitoring():
    return jsonify({
        "message": detector.stop_monitoring()
    })


@app.route("/api/status")
def get_status():
    return jsonify({
        "monitoring": detector.monitoring_status
    })


@app.route("/api/alerts")
def get_alerts():
    return jsonify(get_all_alerts())


@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    clear_all_alerts()

    return jsonify({
        "message": "All alerts cleared successfully."
    })


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
def resolve_single_alert(alert_id):
    resolved = resolve_alert(alert_id)

    if resolved:
        return jsonify({
            "message": "Alert marked as resolved."
        })

    return jsonify({
        "message": "Alert not found."
    }), 404


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )