from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
from otp_service import send_otp
from social_models import register_social_models
from sqlalchemy import or_
from translations import LANGUAGES, RTL_LANGUAGES, translate, home_translate
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from PIL import Image, ImageOps
import uuid

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "instance")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

secret_file = DATA_DIR / "secret_key"
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    if secret_file.exists():
        secret_key = secret_file.read_text(encoding="utf-8").strip()
    else:
        secret_key = secrets.token_hex(32)
        secret_file.write_text(secret_key, encoding="utf-8")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=secret_key,
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DATA_DIR / 'netbook.db'}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_DURATION=timedelta(days=365),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    WTF_CSRF_TIME_LIMIT=3600,
    MAX_CONTENT_LENGTH=10 * 1024 * 1024
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=True, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(500), nullable=True)
    cover_photo = db.Column(db.String(500), nullable=True)
    bio = db.Column(db.String(500), nullable=True)
    location = db.Column(db.String(150), nullable=True)
    university = db.Column(db.String(200), nullable=True)
    language = db.Column(db.String(10), nullable=False, default='bn')
    website = db.Column(db.String(255), nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


Post, FriendRequest, Notification, Story, SocialGroup, GroupMember = register_social_models(db)


class VerificationOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))



@app.context_processor
def inject_language():
    language = "bn"
    if current_user.is_authenticated:
        language = current_user.language or "bn"
    else:
        language = session.get("language", "bn")
    if language not in LANGUAGES:
        language = "bn"
    return {
        "current_language": language,
        "language_dir": "rtl" if language in RTL_LANGUAGES else "ltr",
        "languages": LANGUAGES,
        "t": lambda key: translate(language, key),
        "h": lambda key: home_translate(language, key),
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip().lower()
        contact = request.form.get("contact", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # One contact field: detect email or phone automatically.
        if "@" in contact:
            email = contact.lower()
            phone = None
        else:
            email = None
            phone = contact or None

        if not all([name, username, contact, password, confirm]):
            flash("নাম, Username ও Password পূরণ করুন।", "error")
        elif bool(email) == bool(phone):
            flash("Email অথবা Phone—যেকোনো একটি দিন।", "error")
        elif len(name) > 100 or not re.fullmatch(r"[a-z0-9_]{3,30}", username):
            flash("নাম অথবা Username সঠিক নয়।", "error")
        elif email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("সঠিক Email ঠিকানা দিন।", "error")
        elif phone and not re.fullmatch(r"\+?[0-9]{8,15}", phone):
            flash("সঠিক ফোন নম্বর দিন, প্রয়োজনে দেশের কোডসহ।", "error")
        elif len(password) < 10:
            flash("Password কমপক্ষে ১০ অক্ষরের হতে হবে।", "error")
        elif password != confirm:
            flash("দুটি Password মিলছে না।", "error")
        elif User.query.filter(or_(
            User.username == username,
            User.email == email if email else False,
            User.phone == phone if phone else False
        )).first():
            flash("এই Username, Email অথবা ফোন নম্বর আগে থেকেই ব্যবহৃত।", "error")
        else:
            user = User(
                full_name=name,
                username=username,
                email=email,
                phone=phone,
                password_hash=generate_password_hash(password, method="scrypt"),
                email_verified=False,
                phone_verified=False
            )
            db.session.add(user)
            db.session.commit()
            session["pending_verification_user_id"] = user.id
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            code = f"{secrets.randbelow(1_000_000):06d}"
            db.session.add(VerificationOTP(
                user_id=user.id,
                code_hash=generate_password_hash(code, method="scrypt"),
                expires_at=now + timedelta(minutes=10),
                attempts=0
            ))
            db.session.commit()
            if send_otp(user, code):
                flash("আপনার নির্বাচিত মাধ্যমে OTP পাঠানো হয়েছে।", "success")
            else:
                flash("অ্যাকাউন্ট তৈরি হয়েছে, কিন্তু OTP পাঠানো যায়নি। Email SMTP অথবা SMS gateway কনফিগার করতে হবে।", "warning")
            return redirect(url_for("verify_account"))

    return render_template("register.html")


@app.route("/resend-otp", methods=["POST"])
@limiter.limit("3 per 15 minutes")
def resend_otp():
    user_id = session.get("pending_verification_user_id")
    user = db.session.get(User, user_id) if user_id else None

    if not user:
        flash("অ্যাকাউন্ট পাওয়া যায়নি। আবার Registration করুন।", "error")
        return redirect(url_for("register"))

    verified = user.email_verified if user.email else user.phone_verified
    if verified:
        flash("আপনার অ্যাকাউন্ট ইতিমধ্যে Verify করা হয়েছে।", "success")
        return redirect(url_for("login"))

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    code = f"{secrets.randbelow(1_000_000):06d}"

    new_otp = VerificationOTP(
        user_id=user.id,
        code_hash=generate_password_hash(code, method="scrypt"),
        expires_at=now + timedelta(minutes=10),
        attempts=0
    )

    try:
        db.session.add(new_otp)
        db.session.flush()

        if not send_otp(user, code):
            db.session.rollback()
            flash("OTP পাঠানো যায়নি। আগের OTP থাকলে সেটি এখনো বহাল আছে।", "warning")
            return redirect(url_for("verify_account"))

        VerificationOTP.query.filter(
            VerificationOTP.user_id == user.id,
            VerificationOTP.id != new_otp.id
        ).delete(synchronize_session=False)

        db.session.commit()
        flash("নতুন OTP পাঠানো হয়েছে। ১০ মিনিটের মধ্যে ব্যবহার করুন।", "success")

    except Exception:
        db.session.rollback()
        flash("OTP প্রক্রিয়ায় সমস্যা হয়েছে। আবার চেষ্টা করুন।", "error")

    return redirect(url_for("verify_account"))


@app.route("/verify", methods=["GET", "POST"])
@limiter.limit("10 per 15 minutes")
def verify_account():
    user_id = session.get("pending_verification_user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        flash("আগে একটি অ্যাকাউন্ট তৈরি করুন।", "warning")
        return redirect(url_for("register"))

    verified = user.email_verified if user.email else user.phone_verified
    if verified:
        session.pop("pending_verification_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        otp = VerificationOTP.query.filter_by(user_id=user.id).order_by(VerificationOTP.id.desc()).first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if not otp or otp.expires_at <= now:
            if otp:
                db.session.delete(otp)
                db.session.commit()
            flash("OTP মেয়াদ শেষ হয়েছে। নতুন OTP প্রয়োজন।", "error")
        elif otp.attempts >= 5:
            db.session.delete(otp)
            db.session.commit()
            flash("ভুল চেষ্টার সীমা শেষ। নতুন OTP প্রয়োজন।", "error")
        elif not re.fullmatch(r"[0-9]{6}", code):
            flash("৬ সংখ্যার সঠিক OTP লিখুন।", "error")
        else:
            otp.attempts += 1
            if check_password_hash(otp.code_hash, code):
                if user.email:
                    user.email_verified = True
                else:
                    user.phone_verified = True
                db.session.delete(otp)
                db.session.commit()
                session.pop("pending_verification_user_id", None)
                flash("আপনার অ্যাকাউন্ট Verify হয়েছে। এখন Login করুন।", "success")
                return redirect(url_for("login"))
            db.session.commit()
            flash("OTP সঠিক নয়। আবার চেষ্টা করুন।", "error")

    return render_template("verify.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter(or_(
            User.email == identity,
            User.phone == identity,
            User.username == identity
        )).first()

        if user and user.is_active and check_password_hash(user.password_hash, password):
            verified = user.email_verified if user.email else user.phone_verified
            if not verified:
                session["pending_verification_user_id"] = user.id
                flash("আপনার অ্যাকাউন্ট Verify করুন। OTP দিন।", "warning")
                return redirect(url_for("verify_account"))
            login_user(user, remember=True)
            flash("সফলভাবে Login হয়েছে।", "success")
            return redirect(url_for("home"))

        flash("তথ্য অথবা Password সঠিক নয়।", "error")

    return render_template("login.html")




@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        upload_field = next(
            (name for name in ("profile_picture", "cover_photo")
             if name in request.files),
            None
        )

        if not upload_field:
            flash("ছবি নির্বাচন করুন।", "error")
            return redirect(url_for("profile"))

        uploaded = request.files.get(upload_field)

        if not uploaded or not uploaded.filename:
            flash("একটি ছবি নির্বাচন করুন।", "error")
            return redirect(url_for("profile"))

        try:
            uploaded.stream.seek(0)
            with Image.open(uploaded.stream) as check:
                if check.format not in ("JPEG", "PNG", "WEBP"):
                    raise ValueError("Invalid image format")
                check.verify()

            uploaded.stream.seek(0)
            with Image.open(uploaded.stream) as source:
                image = ImageOps.exif_transpose(source)
                image.thumbnail((2000, 2000))

                if image.mode not in ("RGB", "RGBA"):
                    image = image.convert("RGB")

                folder = BASE_DIR / "static" / "uploads" / "profiles"
                folder.mkdir(parents=True, exist_ok=True)

                filename = f"{uuid.uuid4().hex}.webp"
                image.save(folder / filename, "WEBP", quality=88)

            setattr(
                current_user,
                upload_field,
                f"/static/uploads/profiles/{filename}"
            )
            db.session.commit()
            flash("ছবি সফলভাবে পরিবর্তন হয়েছে।", "success")

        except (ValueError, OSError, Image.DecompressionBombError):
            flash("ছবিটি সঠিক নয়। JPEG, PNG অথবা WEBP ছবি দিন।", "error")

        return redirect(url_for("profile"))

    return render_template("profile.html", profile_user=current_user)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile_details():
    fields = {
        "location": ("location", 150, "Location"),
        "university": ("university", 200, "University"),
        "bio": ("bio", 500, "Bio"),
        "website": ("website", 255, "Website"),
    }

    if request.method == "POST":
        field = request.form.get("field", "")
        if field not in fields:
            flash("সঠিক তথ্য নির্বাচন করুন।", "error")
            return redirect(url_for("edit_profile_details"))

        attribute, limit, label = fields[field]
        value = request.form.get(field, "").strip()

        if len(value) > limit:
            flash(f"{label} নির্ধারিত সীমার বেশি।", "error")
        elif field == "website" and value and not re.match(
            r"^https?://", value, re.I
        ):
            flash("Website লিংক http:// অথবা https:// দিয়ে শুরু করুন।", "error")
        else:
            setattr(current_user, attribute, value or None)
            db.session.commit()
            flash(f"{label} সফলভাবে আপডেট হয়েছে।", "success")

        return redirect(url_for("edit_profile_details"))

    return render_template("edit_profile.html", profile_user=current_user)




@app.route("/settings/language", methods=["GET", "POST"])
def language_settings():
    if request.method == "POST":
        selected = request.form.get("language", "bn")
        if selected not in LANGUAGES:
            flash("সঠিক ভাষা নির্বাচন করুন।", "error")
            return redirect(url_for("language_settings"))

        if current_user.is_authenticated:
            current_user.language = selected
            db.session.commit()
        else:
            session["language"] = selected

        flash(translate(selected, "language_saved"), "success")
        return redirect(url_for("language_settings"))

    return render_template("language_settings.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("আপনি Logout করেছেন।", "success")
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"app": "NET BOOK", "status": "running"}


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
