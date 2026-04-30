from flask import Blueprint, render_template, request
from .detector import analyze_message

main = Blueprint('main', __name__)

@main.route("/", methods=["GET", "POST"])
def home():
    analysis = None
    if request.method == "POST":
        message = request.form.get("message", "")
        analysis = analyze_message(message)
    return render_template("index.html", analysis=analysis)