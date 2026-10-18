import posthog
from flask import Flask, make_response, request, session

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    email = request.form["email"]
    phone = request.form.get("phone")
    app.logger.info("signup %s token=%s", email, request.form.get("token"))
    posthog.capture(email, "signed_up", properties={"email": email, "plan": "free"})
    resp = make_response("ok")
    resp.set_cookie("remember_me", "1", max_age=2592000)
    session["uid"] = 1
    return resp


def delete_account():
    Account.query.filter_by(id=1).delete()
