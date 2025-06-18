import os
import pytesseract
from PIL import Image
import fitz
from flask import (
    Flask,
    jsonify,
    request,
    render_template,
    redirect,
    send_file,
    url_for,
    flash,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import re
from datetime import timedelta, datetime
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Thread
from email.mime.text import MIMEText
import smtplib
from concurrent.futures import ThreadPoolExecutor
import tempfile
from fpdf import FPDF
from google_auth_oauthlib.flow import Flow
import json
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import base64
import logging
from flask import jsonify, session

load_dotenv()

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)

app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(hours=4)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

TESSERACT_PATH = os.getenv(
    "TESSERACT_PATH", r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)
pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

db = SQLAlchemy(app)


class EmailData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    source_file = db.Column(db.String(100))
    date = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    token = db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.password_hash is None:
            return False
        return check_password_hash(self.password_hash, password)


def ocr_page(page):
    try:
        pix = page.get_pixmap()
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        return pytesseract.image_to_string(img)
    except Exception as e:
        logging.error(f"OCR failed on a page: {e}")
        return ""


def extract_text_from_pdf(pdf_file):
    try:
        doc = fitz.open(pdf_file)
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            texts = list(executor.map(ocr_page, doc))
        return "\n".join(texts)
    except Exception as e:
        logging.error(f"Error extracting text from PDF {pdf_file}: {e}")
        return ""


def extract_emails_by_keywords(text, keywords=None):
    if keywords is None:
        keywords = [
            "req.",
            "required",
            "post",
            "posts",
            "job",
            "interview",
            "immediate",
            "vacancy",
            "hiring",
            "executive",
            "assistant",
            "officer",
            "teachers",
            "principal",
            "coordinators",
            "training",
            "experience",
            "recruitment",
            "senior",
            "managers",
            "engineers",
            "architects",
            "accountants",
            "cooks",
            "Reqd",
        ]
    pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.(?:[a-zA-Z0-9-]+\.)*[a-zA-Z]+"
    emails = []
    for match in re.finditer(pattern, text):
        email = match.group()
        start = max(0, match.start() - 700)
        end = min(len(text), match.end() + 700)
        context = text[start:end].lower()
        if any(kw in context for kw in keywords):
            emails.append(email)
    return list(set(emails))


def process_pdfs_background(file_data):
    with app.app_context():
        for file in file_data:
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                    tmp.write(file["content"])
                    filepath = tmp.name

                text = extract_text_from_pdf(filepath)
                emails = extract_emails_by_keywords(text)

                for email in emails:
                    if not EmailData.query.filter_by(email=email).first():
                        db.session.add(
                            EmailData(email=email, source_file=file["filename"])
                        )
                os.remove(filepath)
            except Exception as e:
                logging.error(
                    f"[Background Thread Error] for {file.get('filename', 'N/A')}: {e}",
                    exc_info=True,
                )
        db.session.commit()


def send_via_gmail(user, to, subject, body):
    credentials = Credentials.from_authorized_user_info(json.loads(user.token))
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(build("oauth2", "v2").tokeninfo())
        user.token = credentials.to_json()
        db.session.commit()

    service = build("gmail", "v1", credentials=credentials)
    sender_email = (
        build("oauth2", "v2", credentials=credentials)
        .userinfo()
        .get()
        .execute()
        .get("email")
    )
    if not sender_email:
        raise Exception("Could not retrieve sender's email from Google token.")

    message = MIMEText(body)
    message["to"] = ", ".join(to)
    message["from"] = sender_email
    message["subject"] = subject

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    service.users().messages().send(userId="me", body={"raw": raw_message}).execute()


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("emails"))
    return redirect(url_for("login"))


# @app.route("/register", methods=["GET", "POST"])
# def register():
#     if request.method == "POST":
#         email = request.form["email"]
#         password = request.form["password"]
#         if User.query.filter_by(email=email).first():
#             flash("Email already registered!", "danger")
#             return redirect(url_for("register"))
#         user = User(email=email)
#         user.set_password(password)
#         db.session.add(user)
#         db.session.commit()
#         flash("Registration successful! Please log in.", "success")
#         return redirect(url_for("login"))
#     return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("emails"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session.permanent = True
            flash("Login successful!", "success")
            return redirect(url_for("emails"))
        else:
            flash("Invalid email or password.", "danger")

    client_secrets_info = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "project_id": os.getenv("GOOGLE_PROJECT_ID"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uris": [url_for("google_callback", _external=True)],
        }
    }

    try:
        flow = Flow.from_client_config(
            client_secrets_info,
            scopes=[
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
            ],
            redirect_uri=url_for("google_callback", _external=True),
        )
        authorization_url, state = flow.authorization_url(
            access_type="offline", prompt="consent"
        )
        session["state"] = state
        return render_template("login.html", authorization_url=authorization_url)
    except Exception as e:
        logging.error(f"Error creating Google Auth Flow: {e}", exc_info=True)
        flash("Google Login is not configured correctly on the server.", "danger")
        return render_template("login.html", authorization_url=None)


@app.route("/google_callback")
def google_callback():
    if request.args.get("state") != session.get("state"):
        flash("State mismatch detected! Authentication failed.", "danger")
        return redirect(url_for("login"))

    client_secrets_info = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "project_id": os.getenv("GOOGLE_PROJECT_ID"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uris": [url_for("google_callback", _external=True)],
        }
    }

    flow = Flow.from_client_config(
        client_secrets_info,
        scopes=[
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
        state=session["state"],
        redirect_uri=url_for("google_callback", _external=True),
    )

    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        user_info_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        email = user_info["email"]

        user = User.query.filter_by(email=email).first()
        if user:
            user.token = credentials.to_json()
        else:
            user = User(email=email, password_hash=None, token=credentials.to_json())
            db.session.add(user)

        db.session.commit()
        session["user_id"] = user.id
        flash("Successfully logged in with Google!", "success")
        return redirect(url_for("emails"))

    except Exception as e:
        flash(f"Error during Google authentication: {e}", "danger")
        logging.error(f"Google OAuth Error: {e}", exc_info=True)
        return redirect(url_for("login"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        files = request.files.getlist("pdfs[]")
        if not files or all(not f.filename for f in files):
            flash("No files selected!", "warning")
            return redirect(request.url)

        file_data = [
            {"filename": f.filename, "content": f.read()}
            for f in files
            if f.filename.lower().endswith(".pdf")
        ]

        if not file_data:
            flash("No valid PDF files were uploaded.", "warning")
            return redirect(request.url)

        thread = Thread(target=process_pdfs_background, args=(file_data,))
        thread.start()
        flash(
            f"{len(file_data)} PDF(s) uploaded. Extraction is running in the background.",
            "info",
        )
        return redirect(url_for("emails"))
    return render_template("upload.html")


@app.route("/emails")
def emails():
    if "user_id" not in session:
        flash("Please log in to view this page.", "warning")
        return redirect(url_for("login"))
    page = request.args.get("page", 1, type=int)
    per_page = 10
    pagination = EmailData.query.order_by(EmailData.date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template("emails.html", data=pagination.items, pagination=pagination)


@app.route("/api/get_all_emails")
def get_all_emails():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    all_emails = (
        EmailData.query.with_entities(func.trim(EmailData.email))
        .filter(EmailData.email != None, EmailData.email != "")
        .distinct()
        .all()
    )
    email_list = [e[0] for e in all_emails]
    return jsonify({"emails": email_list})


@app.route("/compose_and_send", methods=["POST"])
def compose_and_send():
    if "user_id" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))

    # Get data from modal form
    selected_emails_raw = request.form.get("modal_selected_emails", "")
    subject = request.form.get("subject", "Job Opportunity Information")
    body = request.form.get("body", "")

    selected_emails = [
        email.strip() for email in selected_emails_raw.split(",") if email.strip()
    ]

    if not selected_emails:
        flash("No emails were selected to send.", "warning")
        return redirect(url_for("emails"))

    sender = User.query.get(session["user_id"])
    if not sender or not sender.token:
        flash("Gmail authorization is required to send emails.", "danger")
        return redirect(url_for("emails"))

    try:
        send_via_gmail(
            sender, selected_emails, subject, body
        )  # Pass the full list at once
        flash(
            f"Email sent successfully to {len(selected_emails)} recipient(s).",
            "success",
        )
    except Exception as e:
        logging.error(f"Failed to send group email: {e}", exc_info=True)
        flash("Failed to send email. Please check logs.", "danger")

    return redirect(url_for("emails"))


@app.route("/report", methods=["GET", "POST"])
def report():
    if "user_id" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))
    emails = []
    start, end = "", ""
    if request.method == "POST":
        start = request.form.get("startdate")
        end = request.form.get("enddate")
        try:
            start_dt = datetime.strptime(start, "%Y-%m-%d")
            end_dt = datetime.strptime(end, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59
            )
            emails = (
                EmailData.query.filter(EmailData.date.between(start_dt, end_dt))
                .order_by(EmailData.date.asc())
                .all()
            )
            if not emails:
                flash("No emails found in the selected date range.", "warning")
        except (ValueError, TypeError):
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
    return render_template("report.html", emails=emails, start=start, end=end)


@app.route("/report/pdf")
def report_pdf():
    if "user_id" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))
    start_str = request.args.get("start")
    end_str = request.args.get("end")
    if not start_str or not end_str:
        flash("Date range not provided for PDF report.", "warning")
        return redirect(url_for("report"))

    try:
        start_dt = datetime.strptime(start_str, "%Y-%m-%d")
        end_dt = datetime.strptime(end_str, "%Y-%m-%d").replace(
            hour=23, minute=59, second=59
        )
        emails = (
            EmailData.query.filter(EmailData.date.between(start_dt, end_dt))
            .order_by(EmailData.date.asc())
            .all()
        )
        if not emails:
            flash(
                "No emails to generate a PDF for in the selected date range.", "warning"
            )
            return redirect(url_for("report"))

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, f"Email Report ({start_str} to {end_str})", 0, 1, "C")
        pdf.ln(10)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(80, 10, "Email", 1, 0, "C")
        pdf.cell(70, 10, "Source File", 1, 0, "C")
        pdf.cell(40, 10, "Extracted Date", 1, 1, "C")
        pdf.set_font("Arial", "", 10)
        for e in emails:
            pdf.cell(80, 10, e.email, 1, 0)
            pdf.cell(70, 10, e.source_file, 1, 0)
            pdf.cell(40, 10, e.date.strftime("%Y-%m-%d"), 1, 1)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            pdf_path = tmp.name
            pdf.output(pdf_path)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"report_{start_str}_to_{end_str}.pdf",
        )
    except Exception as e:
        logging.error(f"Failed to generate PDF report: {e}", exc_info=True)
        flash("An error occurred while generating the PDF report.", "danger")
        return redirect(url_for("report"))


@app.route("/delete/<int:email_id>", methods=["POST"])
def delete_email(email_id):
    if "user_id" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))
    email = EmailData.query.get_or_404(email_id)
    db.session.delete(email)
    db.session.commit()
    flash("Email has been removed.", "success")
    return redirect(url_for("emails"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been successfully logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
