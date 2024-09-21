import json
import logging
import os
from datetime import datetime
from typing import Optional

import markdown2
import requests
from dotenv import load_dotenv
from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "your_secret_key"
DATA_FOLDER = "data"

load_dotenv(dotenv_path=".env")

if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)

RECAPTCHA_SECRET_KEY = os.environ["RECAPTCHA_SECRET_KEY"]


def get_user_file_path(user_id: str) -> str:
    return os.path.join(DATA_FOLDER, f"{user_id}.json")


def handle_error(message: str, status_code: int = 500) -> Response:
    logger.error(f"Error: {message}, Status Code: {status_code}")
    return jsonify({"error": message}), status_code


@app.route("/", methods=["GET", "POST"])
def main() -> str:
    if "user_id" in session:
        logger.info("User already logged in, redirecting to mypage.")
        return redirect(url_for("mypage"))

    error_message: Optional[str] = None
    auto_login: bool = False

    if request.method == "POST":
        user_id: str = request.form["user_id"]
        password: str = request.form["password"]
        auto_login = "auto_login" in request.form
        user_file_path: str = get_user_file_path(user_id)

        if not os.path.exists(user_file_path):
            error_message = "사용자가 존재하지 않습니다."
            logger.warning(f"Login attempt failed: User {user_id} does not exist.")
        else:
            with open(user_file_path, "r", encoding="utf-8") as file:
                user_data = json.loads(file.read())
            if check_password_hash(user_data["password"], password):
                session["user_id"] = user_id
                response = redirect(url_for("mypage"))
                if auto_login:
                    response.set_cookie(
                        "user_id", user_id, max_age=30 * 24 * 60 * 60
                    )  # 30 days
                logger.info(f"User {user_id} logged in successfully.")
                return response
            error_message = "비밀번호가 잘못되었습니다."
            logger.warning(
                f"Login attempt failed: Incorrect password for user {user_id}."
            )

    user_id_cookie = request.cookies.get("user_id")
    if user_id_cookie:
        session["user_id"] = user_id_cookie
        logger.info(f"User {user_id_cookie} logged in via cookie.")
        return redirect(url_for("mypage"))

    return render_template("login.html", error=error_message, auto_login=auto_login)


@app.route("/signup", methods=["GET", "POST"])
def signup() -> str:
    error_message: Optional[str] = None
    if request.method == "POST":
        user_id: str = request.form["user_id"]
        password: str = request.form["password"]
        recaptcha_response: str = request.form["g-recaptcha-response"]

        payload = {"secret": RECAPTCHA_SECRET_KEY, "response": recaptcha_response}
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify", data=payload
        )
        result = response.json()

        if not result.get("success"):
            error_message = "로봇이 아닐 경우 체크해 주세요."
            logger.warning("Signup attempt failed: reCAPTCHA validation failed.")
        elif len(password) < 8 or password.isalpha():
            error_message = "비밀번호는 최소 8자 이상이어야 하며 숫자 또는 특수 문자를 포함해야 합니다."
            logger.warning("Signup attempt failed: Password does not meet criteria.")
        else:
            user_file_path: str = get_user_file_path(user_id)
            if os.path.exists(user_file_path):
                error_message = "사용자가 이미 존재합니다."
                logger.warning(f"Signup attempt failed: User {user_id} already exists.")
            else:
                hashed_password = generate_password_hash(password)
                with open(user_file_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {"password": hashed_password, "memo": []},
                        file,
                        ensure_ascii=False,
                    )
                logger.info(f"User {user_id} signed up successfully.")
                return redirect(url_for("main"))

    return render_template("signup.html", error=error_message)


@app.route("/add_memo", methods=["POST"])
def add_memo() -> Response:
    try:
        user_id: Optional[str] = session.get("user_id")
        if not user_id:
            return handle_error("로그인이 필요합니다.", 403)

        user_file_path: str = get_user_file_path(user_id)

        with open(user_file_path, "r", encoding="utf-8") as file:
            user_data = json.loads(file.read())

        memo_content: str = request.form["memo"]
        index: int = len(user_data.get("memo", [])) + 1
        timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_memo = {"content": memo_content, "index": index, "timestamp": timestamp}

        user_data.setdefault("memo", []).append(new_memo)

        with open(user_file_path, "w", encoding="utf-8") as file:
            json.dump(user_data, file, ensure_ascii=False)

        logger.info(f"Memo added for user {user_id}.")
        return redirect(url_for("mypage"))

    except Exception as e:
        logger.error(f"Error occurred while adding memo: {e}")
        return handle_error("문제가 발생했습니다. 다시 시도해주세요.")


@app.route("/delete_memo/<int:index>", methods=["POST"])
def delete_memo(index: int) -> Response:
    try:
        user_id: Optional[str] = session.get("user_id")
        if not user_id:
            return handle_error("로그인이 필요합니다.", 403)

        user_file_path: str = get_user_file_path(user_id)

        with open(user_file_path, "r", encoding="utf-8") as file:
            user_data = json.loads(file.read())

        if "memo" in user_data and 0 <= index < len(user_data["memo"]):
            user_data["memo"].pop(index)
            for i, memo in enumerate(user_data["memo"]):
                memo["index"] = i + 1

            with open(user_file_path, "w", encoding="utf-8") as file:
                json.dump(user_data, file, ensure_ascii=False)

            logger.info(f"Memo {index} deleted for user {user_id}.")
            return redirect(url_for("mypage"))
        else:
            return handle_error("메모가 존재하지 않습니다.", 404)

    except Exception as e:
        logger.error(f"Error occurred while deleting memo: {e}")
        return handle_error("문제가 발생했습니다. 다시 시도해주세요.")


@app.route("/edit_memo/<int:index>", methods=["POST"])
def edit_memo(index: int) -> Response:
    try:
        user_id: Optional[str] = session.get("user_id")
        if not user_id:
            return handle_error("로그인이 필요합니다.", 403)

        user_file_path: str = get_user_file_path(user_id)

        with open(user_file_path, "r", encoding="utf-8") as file:
            user_data = json.loads(file.read())

        if "memo" in user_data and 0 <= index < len(user_data["memo"]):
            user_data["memo"][index]["content"] = request.form["memo"]

            with open(user_file_path, "w", encoding="utf-8") as file:
                json.dump(user_data, file, ensure_ascii=False)

            logger.info(f"Memo {index} edited for user {user_id}.")
            return redirect(url_for("mypage"))
        else:
            return handle_error("메모가 존재하지 않습니다.", 404)

    except Exception as e:
        logger.error(f"Error occurred while editing memo: {e}")
        return handle_error("문제가 발생했습니다. 다시 시도해주세요.")


@app.route("/delete_all_memos", methods=["POST"])
def delete_all_memos() -> Response:
    try:
        user_id: Optional[str] = session.get("user_id")
        if not user_id:
            return handle_error("로그인이 필요합니다.", 403)

        user_file_path: str = get_user_file_path(user_id)

        with open(user_file_path, "r", encoding="utf-8") as file:
            user_data = json.loads(file.read())

        user_data["memo"] = []

        with open(user_file_path, "w", encoding="utf-8") as file:
            json.dump(user_data, file, ensure_ascii=False)

        logger.info(f"All memos deleted for user {user_id}.")
        return redirect(url_for("mypage"))

    except Exception as e:
        logger.error(f"Error occurred while deleting all memos: {e}")
        return handle_error("문제가 발생했습니다. 다시 시도해주세요.")


@app.route("/delete_account", methods=["POST"])
def delete_account() -> Response:
    try:
        user_id: Optional[str] = session.get("user_id")
        if not user_id:
            return handle_error("로그인이 필요합니다.", 403)

        user_file_path: str = get_user_file_path(user_id)

        if os.path.exists(user_file_path):
            os.remove(user_file_path)

        session.pop("user_id", None)
        response = redirect(url_for("main"))
        response.delete_cookie("user_id")
        logger.info(f"User {user_id} account deleted.")
        return response

    except Exception as e:
        logger.error(f"Error occurred while deleting account: {e}")
        return handle_error("문제가 발생했습니다. 다시 시도해주세요.")


@app.route("/mypage")
def mypage() -> str:
    user_id: Optional[str] = session.get("user_id")
    if not user_id:
        return handle_error("로그인이 필요합니다.", 403)

    user_file_path: str = get_user_file_path(user_id)
    if not os.path.exists(user_file_path):
        return handle_error("사용자 정보가 존재하지 않습니다.", 404)

    with open(user_file_path, "r", encoding="utf-8") as file:
        user_data = json.loads(file.read())

    for memo in user_data.get("memo", []):
        memo["html_content"] = markdown2.markdown(memo["content"], extras=["break-on-newline"])

    logger.info(f"User {user_id} accessed mypage.")
    return render_template("mypage.html", user_id=user_id, memo=user_data.get("memo"))


@app.route("/logout")
def logout() -> Response:
    session.pop("user_id", None)
    response = redirect(url_for("main"))
    response.delete_cookie("user_id")
    logger.info("User logged out.")
    return response


@app.errorhandler(404)
def not_found(e: Exception) -> tuple[str, int]:
    logger.warning(f"404 error: {e}")
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e: Exception) -> tuple[str, int]:
    logger.error(f"500 error: {e}")
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True)