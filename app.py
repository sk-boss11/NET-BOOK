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

database_url = os.environ.get("DATABASE_URL", "").strip()
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=secret_key,
    SQLALCHEMY_DATABASE_URI=database_url or f"sqlite:///{DATA_DIR / 'netbook.db'}",
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


Post, FriendRequest, Notification, Story, SocialGroup, GroupMember, Reel, ReelLike, ReelComment = register_social_models(db)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)





class VerificationOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class PasswordResetOTP(db.Model):
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
    posts = (
        Post.query
        .order_by(Post.created_at.desc(), Post.id.desc())
        .limit(30)
        .all()
    )
    post_authors = {
        post.id: db.session.get(User, post.user_id)
        for post in posts
    }
    return render_template(
        "index.html",
        posts=posts,
        post_authors=post_authors
    )


@app.route("/posts/create", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def create_post():
    content = request.form.get("content", "").strip()

    if not content:
        flash("পোস্টের লেখা খালি রাখা যাবে না।", "error")
    elif len(content) > 5000:
        flash("পোস্ট সর্বোচ্চ ৫০০০ অক্ষরের হতে পারবে।", "error")
    else:
        try:
            post = Post(user_id=current_user.id, content=content)
            db.session.add(post)
            db.session.commit()
            flash("আপনার পোস্ট সফলভাবে প্রকাশিত হয়েছে।", "success")
        except Exception:
            db.session.rollback()
            app.logger.exception("Post creation failed")
            flash("পোস্ট প্রকাশ করা যায়নি। আবার চেষ্টা করুন।", "error")

    return redirect(url_for("home"))


@app.route("/posts/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = db.session.get(Post, post_id)

    if post is None:
        flash("পোস্টটি পাওয়া যায়নি।", "error")
    elif post.user_id != current_user.id:
        flash("শুধু নিজের পোস্ট মুছে ফেলতে পারবেন।", "error")
    else:
        try:
            db.session.delete(post)
            db.session.commit()
            flash("পোস্ট মুছে ফেলা হয়েছে।", "success")
        except Exception:
            db.session.rollback()
            app.logger.exception("Post deletion failed")
            flash("পোস্ট মুছে ফেলা যায়নি।", "error")

    return redirect(url_for("home"))


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

        if "@" in contact:
            email, phone = contact.lower(), None
        else:
            email, phone = None, contact or None

        if not all([name, username, contact, password, confirm]):
            flash("সব প্রয়োজনীয় তথ্য পূরণ করুন।", "error")
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
                email_verified=True,
                phone_verified=True
            )
            try:
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
                flash("অ্যাকাউন্ট তৈরি হয়েছে। স্বাগতম NET BOOK-এ!", "success")
                return redirect(url_for("home"))
            except Exception:
                db.session.rollback()
                app.logger.exception("Registration failed")
                flash("অ্যাকাউন্ট তৈরি করা যায়নি। আবার চেষ্টা করুন।", "error")

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



@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per 15 minutes")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()
        user = User.query.filter(or_(
            User.email == identity,
            User.phone == identity,
            User.username == identity
        )).first()

        session.pop("password_reset_user_id", None)
        session.pop("password_reset_verified", None)

        if user and user.is_active and user.email:
            code = f"{secrets.randbelow(1_000_000):06d}"

            if send_otp(user, code):
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                try:
                    PasswordResetOTP.query.filter_by(user_id=user.id).delete()
                    db.session.add(PasswordResetOTP(
                        user_id=user.id,
                        code_hash=generate_password_hash(code, method="scrypt"),
                        expires_at=now + timedelta(minutes=10),
                        attempts=0
                    ))
                    db.session.commit()
                    session["password_reset_user_id"] = user.id
                    flash("আপনার Email-এ OTP পাঠানো হয়েছে। ১০ মিনিটের মধ্যে ব্যবহার করুন।", "success")
                    return redirect(url_for("verify_password_reset"))
                except Exception:
                    db.session.rollback()
                    flash("OTP প্রক্রিয়ায় সমস্যা হয়েছে। আবার চেষ্টা করুন।", "error")
            else:
                flash("OTP পাঠানো যায়নি। Email SMTP কনফিগারেশন পরীক্ষা করুন।", "error")
        else:
            flash("এই তথ্যের জন্য Password Recovery উপলব্ধ নয়। Verified Email অ্যাকাউন্ট ব্যবহার করুন।", "warning")

    return render_template("forgot_password.html")


@app.route("/verify-password-reset", methods=["GET", "POST"])
@limiter.limit("10 per 15 minutes")
def verify_password_reset():
    user_id = session.get("password_reset_user_id")
    user = db.session.get(User, user_id) if user_id else None

    if not user or not user.is_active:
        session.pop("password_reset_user_id", None)
        flash("প্রথমে Password Recovery শুরু করুন।", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        otp = PasswordResetOTP.query.filter_by(user_id=user.id).first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if not otp or otp.expires_at <= now or otp.attempts >= 5:
            if otp:
                db.session.delete(otp)
                db.session.commit()
            session.pop("password_reset_user_id", None)
            flash("OTP-এর মেয়াদ শেষ অথবা চেষ্টার সীমা শেষ। আবার শুরু করুন।", "error")
            return redirect(url_for("forgot_password"))

        if not re.fullmatch(r"[0-9]{6}", code):
            flash("৬ সংখ্যার OTP লিখুন।", "error")
        else:
            otp.attempts += 1
            if check_password_hash(otp.code_hash, code):
                if user.email:
                    user.email_verified = True
                db.session.commit()
                session["password_reset_verified"] = True
                flash("OTP সঠিক। এবার নতুন Password দিন।", "success")
                return redirect(url_for("reset_password"))

            db.session.commit()
            flash("OTP সঠিক নয়। আবার চেষ্টা করুন।", "error")

    return render_template("verify_password_reset.html")


@app.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes")
def reset_password():
    user_id = session.get("password_reset_user_id")
    user = db.session.get(User, user_id) if user_id else None

    otp = PasswordResetOTP.query.filter_by(user_id=user.id).first() if user else None
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if (
        not user
        or not user.is_active
        or not session.get("password_reset_verified")
        or not otp
        or otp.expires_at <= now
        or otp.attempts >= 5
    ):
        if otp:
            db.session.delete(otp)
            db.session.commit()
        session.pop("password_reset_user_id", None)
        session.pop("password_reset_verified", None)
        flash("OTP-এর মেয়াদ শেষ অথবা আগে OTP Verify করা হয়নি। আবার শুরু করুন।", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 10:
            flash("Password কমপক্ষে ১০ অক্ষরের হতে হবে।", "error")
        elif password != confirm:
            flash("দুটি Password মিলছে না।", "error")
        else:
            user.password_hash = generate_password_hash(password, method="scrypt")
            PasswordResetOTP.query.filter_by(user_id=user.id).delete()
            db.session.commit()

            session.pop("password_reset_user_id", None)
            session.pop("password_reset_verified", None)
            flash("Password সফলভাবে পরিবর্তন হয়েছে। এখন নতুন Password দিয়ে Login করুন।", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        if "@" in identity:
            user = User.query.filter_by(email=identity.lower()).first()
        else:
            user = User.query.filter_by(phone=identity).first()

        if user and user.is_active and check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            flash("সফলভাবে Login হয়েছে।", "success")
            return redirect(url_for("home"))

        flash("ফোন নম্বর অথবা Email এবং Password সঠিক নয়।", "error")

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
            return redirect(url_for("profile"))

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

        return redirect(url_for("profile"))

    selected_field = request.args.get("field", "")
    if selected_field not in fields:
        selected_field = ""
    return render_template(
        "edit_profile.html",
        profile_user=current_user,
        selected_field=selected_field
    )




@app.route("/messages")
@login_required
def messages():
    accepted = FriendRequest.query.filter(
        FriendRequest.status == "accepted",
        or_(
            FriendRequest.sender_id == current_user.id,
            FriendRequest.receiver_id == current_user.id
        )
    ).all()

    friend_ids = {
        item.receiver_id if item.sender_id == current_user.id
        else item.sender_id
        for item in accepted
    }

    friends_list = User.query.filter(
        User.id.in_(friend_ids),
        User.is_active.is_(True)
    ).order_by(User.full_name.asc()).all() if friend_ids else []

    return render_template("messages.html", friends_list=friends_list)


@app.route("/messages/<int:user_id>", methods=["GET", "POST"])
@login_required
def chat(user_id):
    friend = db.session.get(User, user_id)

    if not friend or not friend.is_active or friend.id == current_user.id:
        flash("ব্যবহারকারীকে পাওয়া যায়নি।", "error")
        return redirect(url_for("messages"))

    friendship = FriendRequest.query.filter(
        FriendRequest.status == "accepted",
        or_(
            db.and_(
                FriendRequest.sender_id == current_user.id,
                FriendRequest.receiver_id == friend.id
            ),
            db.and_(
                FriendRequest.sender_id == friend.id,
                FriendRequest.receiver_id == current_user.id
            )
        )
    ).first()

    if not friendship:
        flash("শুধু Accepted Friends-দের সঙ্গে Chat করা যাবে।", "error")
        return redirect(url_for("messages"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content:
            flash("মেসেজ লিখুন।", "error")
        elif len(content) > 5000:
            flash("মেসেজ সর্বোচ্চ ৫০০০ অক্ষরের হতে পারবে।", "error")
        else:
            db.session.add(Message(
                sender_id=current_user.id,
                recipient_id=friend.id,
                content=content
            ))
            db.session.commit()
        return redirect(url_for("chat", user_id=friend.id))

    chat_messages = Message.query.filter(
        or_(
            db.and_(
                Message.sender_id == current_user.id,
                Message.recipient_id == friend.id
            ),
            db.and_(
                Message.sender_id == friend.id,
                Message.recipient_id == current_user.id
            )
        )
    ).order_by(Message.created_at.asc(), Message.id.asc()).all()

    Message.query.filter_by(
        sender_id=friend.id,
        recipient_id=current_user.id,
        is_read=False
    ).update({"is_read": True})
    db.session.commit()

    return render_template(
        "chat.html",
        friend=friend,
        chat_messages=chat_messages
    )


@app.route("/friends")
@login_required
def friends():
    page = max(request.args.get("page", 1, type=int), 1)
    search = request.args.get("q", "").strip()[:80]

    query = User.query.filter(
        User.id != current_user.id,
        User.is_active.is_(True)
    )

    if search:
        query = query.filter(or_(
            User.full_name.ilike(f"%{search}%"),
            User.username.ilike(f"%{search}%")
        ))

    users_page = query.order_by(User.full_name.asc()).paginate(
        page=page, per_page=20, error_out=False
    )

    incoming_requests = FriendRequest.query.filter_by(
        receiver_id=current_user.id, status="pending"
    ).order_by(FriendRequest.created_at.desc()).all()

    outgoing_requests = FriendRequest.query.filter_by(
        sender_id=current_user.id, status="pending"
    ).all()

    accepted = FriendRequest.query.filter(
        FriendRequest.status == "accepted",
        or_(
            FriendRequest.sender_id == current_user.id,
            FriendRequest.receiver_id == current_user.id
        )
    ).all()

    friend_ids = {
        item.receiver_id if item.sender_id == current_user.id
        else item.sender_id for item in accepted
    }

    incoming_senders = {item.id: db.session.get(User, item.sender_id) for item in incoming_requests}

    return render_template(
        "friends.html",
        users=users_page.items,
        users_page=users_page,
        incoming_requests=incoming_requests,
        incoming_senders=incoming_senders,
        friend_ids=friend_ids,
        outgoing_ids={item.receiver_id for item in outgoing_requests},
        outgoing_requests_map={item.receiver_id: item.id for item in outgoing_requests},
        incoming_ids={item.sender_id for item in incoming_requests},
        search=search
    )


@app.route("/friends/request/<int:user_id>", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def send_friend_request(user_id):
    if user_id == current_user.id:
        flash("নিজেকে Friend Request পাঠানো যাবে না।", "error")
        return redirect(url_for("friends"))

    target = db.session.get(User, user_id)
    if not target or not target.is_active:
        flash("ব্যবহারকারীকে পাওয়া যায়নি।", "error")
        return redirect(url_for("friends"))

    existing = FriendRequest.query.filter(or_(
        db.and_(
            FriendRequest.sender_id == current_user.id,
            FriendRequest.receiver_id == user_id
        ),
        db.and_(
            FriendRequest.sender_id == user_id,
            FriendRequest.receiver_id == current_user.id
        )
    )).all()

    if any(item.status == "accepted" for item in existing):
        flash("আপনারা ইতিমধ্যে Friends।", "info")
        return redirect(url_for("friends"))

    reverse_pending = any(
        item.sender_id == user_id
        and item.receiver_id == current_user.id
        and item.status == "pending"
        for item in existing
    )
    if reverse_pending:
        flash("এই ব্যক্তির Friend Request আপনার অপেক্ষায় আছে।", "info")
        return redirect(url_for("friends"))

    own_request = next((
        item for item in existing
        if item.sender_id == current_user.id
        and item.receiver_id == user_id
    ), None)

    if own_request and own_request.status == "pending":
        flash("আপনি ইতিমধ্যে Request পাঠিয়েছেন।", "info")
    elif own_request:
        own_request.status = "pending"
        own_request.created_at = datetime.utcnow()
        db.session.commit()
        flash("Friend Request আবার পাঠানো হয়েছে।", "success")
    else:
        db.session.add(FriendRequest(
            sender_id=current_user.id,
            receiver_id=user_id,
            status="pending"
        ))
        db.session.commit()
        flash("Friend Request পাঠানো হয়েছে।", "success")

    return redirect(url_for("friends"))


@app.route("/friends/accept/<int:request_id>", methods=["POST"])
@login_required
def accept_friend_request(request_id):
    item = db.session.get(FriendRequest, request_id)

    if not item or item.receiver_id != current_user.id or item.status != "pending":
        flash("এই Friend Request গ্রহণ করা যাচ্ছে না।", "error")
        return redirect(url_for("friends"))

    reverse = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=item.sender_id,
        status="accepted"
    ).first()

    if reverse:
        item.status = "rejected"
        db.session.commit()
        flash("আপনারা ইতিমধ্যে Friends।", "info")
        return redirect(url_for("friends"))

    item.status = "accepted"
    db.session.commit()
    flash("Friend Request গ্রহণ হয়েছে। এখন আপনারা দুজন Friends।", "success")
    return redirect(url_for("friends"))


@app.route("/friends/reject/<int:request_id>", methods=["POST"])
@login_required
def reject_friend_request(request_id):
    item = db.session.get(FriendRequest, request_id)

    if not item or item.receiver_id != current_user.id or item.status != "pending":
        flash("এই Friend Request প্রত্যাখ্যান করা যাচ্ছে না।", "error")
        return redirect(url_for("friends"))

    item.status = "rejected"
    db.session.commit()
    flash("Friend Request প্রত্যাখ্যান করা হয়েছে।", "success")
    return redirect(url_for("friends"))


@app.route("/friends/cancel/<int:request_id>", methods=["POST"])
@login_required
def cancel_friend_request(request_id):
    item = db.session.get(FriendRequest, request_id)

    if not item or item.sender_id != current_user.id or item.status != "pending":
        flash("এই Request বাতিল করা যাচ্ছে না।", "error")
        return redirect(url_for("friends"))

    item.status = "rejected"
    db.session.commit()
    flash("Friend Request বাতিল করা হয়েছে।", "success")
    return redirect(url_for("friends"))


@app.route("/users/<username>")
@login_required
def public_profile(username):
    profile_user = User.query.filter_by(username=username).first_or_404()
    return render_template("public_profile.html", profile_user=profile_user)


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
