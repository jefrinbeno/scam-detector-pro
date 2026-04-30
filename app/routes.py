from flask import Blueprint, render_template, request
from .detector import check_scam

main = Blueprint('main', __name__)

@main.route("/", methods=["GET", "POST"])
def home():
    result = ""
    if request.method == "POST":
        message = request.form.get("message", "")
        result = check_scam(message)
    return render_template("index.html", result=result)