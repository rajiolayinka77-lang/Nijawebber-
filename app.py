import os
import re
from datetime import datetime
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template,
    flash,
    abort
)
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-in-render"
)

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    print("WARNING: DATABASE_URL is not configured.")


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is missing."
        )

    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(30) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blogs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            title VARCHAR(200) NOT NULL,
            slug VARCHAR(220) UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            blog_id INTEGER NOT NULL REFERENCES blogs(id)
                ON DELETE CASCADE,
            title VARCHAR(250) NOT NULL,
            slug VARCHAR(280) UNIQUE NOT NULL,
            content TEXT NOT NULL,
            published BOOLEAN DEFAULT TRUE,
            views INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS businesses (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            name VARCHAR(200) NOT NULL,
            description TEXT,
            phone VARCHAR(50),
            whatsapp VARCHAR(50),
            location VARCHAR(200),
            website VARCHAR(300),
            category VARCHAR(120),
            views INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS page_views (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id)
                ON DELETE SET NULL,
            page_type VARCHAR(50) NOT NULL,
            page_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def slugify(text):
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "item"


def unique_slug(cur, table, title):
    base = slugify(title)
    slug = base
    number = 2

    while True:
        cur.execute(
            f"SELECT id FROM {table} WHERE slug = %s",
            (slug,)
        )

        if not cur.fetchone():
            return slug

        slug = f"{base}-{number}"
        number += 1


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM users WHERE id = %s",
        (user_id,)
    )

    user = cur.fetchone()

    cur.close()
    conn.close()

    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if not user or user["role"] != "admin":
            abort(403)

        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_user():
    return {
        "current_user": current_user()
    }


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.route("/")
def home():
    query = request.args.get("q", "").strip()

    results = []

    if query:
        conn = get_db()
        cur = conn.cursor()

        search = f"%{query}%"

        cur.execute("""
            SELECT
                p.id,
                p.title,
                p.slug,
                p.content,
                b.title AS blog_title,
                u.name AS author
            FROM posts p
            JOIN blogs b ON b.id = p.blog_id
            JOIN users u ON u.id = b.user_id
            WHERE p.published = TRUE
            AND (
                p.title ILIKE %s
                OR p.content ILIKE %s
                OR b.title ILIKE %s
            )
            ORDER BY p.created_at DESC
            LIMIT 30
        """, (search, search, search))

        results = cur.fetchall()

        cur.close()
        conn.close()

    return render_template(
        "home.html",
        query=query,
        results=results
    )


# ---------------------------------------------------------
# REGISTER
# ---------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please complete all fields.", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT id FROM users WHERE email = %s",
            (email,)
        )

        if cur.fetchone():
            cur.close()
            conn.close()

            flash("An account with this email already exists.", "danger")
            return redirect(url_for("login"))

        password_hash = generate_password_hash(password)

        cur.execute("""
            INSERT INTO users
            (name, email, password_hash)
            VALUES (%s, %s, %s)
            RETURNING id
        """, (name, email, password_hash))

        user_id = cur.fetchone()["id"]

        conn.commit()

        cur.close()
        conn.close()

        session["user_id"] = user_id

        flash(
            "Welcome to NijaWeber! Your free account is ready.",
            "success"
        )

        return redirect(url_for("dashboard"))

    return render_template("register.html")


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        )

        user = cur.fetchone()

        cur.close()
        conn.close()

        if not user or not check_password_hash(
            user["password_hash"],
            password
        ):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    user = current_user()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM blogs
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (user["id"],))

    blogs = cur.fetchall()

    cur.execute("""
        SELECT *
        FROM businesses
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (user["id"],))

    businesses = cur.fetchall()

    cur.execute("""
        SELECT COALESCE(SUM(p.views), 0) AS total_views
        FROM posts p
        JOIN blogs b ON b.id = p.blog_id
        WHERE b.user_id = %s
    """, (user["id"],))

    total_views = cur.fetchone()["total_views"]

    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        blogs=blogs,
        businesses=businesses,
        total_views=total_views
    )


# ---------------------------------------------------------
# CREATE BLOG
# ---------------------------------------------------------

@app.route("/blog/create", methods=["POST"])
@login_required
def create_blog():

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()

    if not title:
        flash("Blog title is required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cur = conn.cursor()

    slug = unique_slug(cur, "blogs", title)

    cur.execute("""
        INSERT INTO blogs
        (user_id, title, slug, description)
        VALUES (%s, %s, %s, %s)
    """, (
        session["user_id"],
        title,
        slug,
        description
    ))

    conn.commit()

    cur.close()
    conn.close()

    flash("Your free Blogger Workspace has been created!", "success")

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# BLOG
# ---------------------------------------------------------

@app.route("/blog/<slug>")
def blog(slug):

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM blogs WHERE slug = %s",
        (slug,)
    )

    blog_data = cur.fetchone()

    if not blog_data:
        cur.close()
        conn.close()
        abort(404)

    cur.execute("""
        SELECT
            p.*,
            u.name AS author
        FROM posts p
        JOIN blogs b ON b.id = p.blog_id
        JOIN users u ON u.id = b.user_id
        WHERE p.blog_id = %s
        AND p.published = TRUE
        ORDER BY p.created_at DESC
    """, (blog_data["id"],))

    posts = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "blog.html",
        blog=blog_data,
        posts=posts
    )


# ---------------------------------------------------------
# CREATE POST
# ---------------------------------------------------------

@app.route("/blog/<int:blog_id>/post", methods=["POST"])
@login_required
def create_post(blog_id):

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if not title or not content:
        flash("Title and content are required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM blogs
        WHERE id = %s
        AND user_id = %s
    """, (blog_id, session["user_id"]))

    blog_data = cur.fetchone()

    if not blog_data:
        cur.close()
        conn.close()
        abort(403)

    slug = unique_slug(cur, "posts", title)

    cur.execute("""
        INSERT INTO posts
        (blog_id, title, slug, content)
        VALUES (%s, %s, %s, %s)
    """, (
        blog_id,
        title,
        slug,
        content
    ))

    conn.commit()

    cur.close()
    conn.close()

    flash("Article published successfully!", "success")

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# POST VIEW
# ---------------------------------------------------------

@app.route("/post/<slug>")
def post(slug):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            p.*,
            b.title AS blog_title,
            u.name AS author
        FROM posts p
        JOIN blogs b ON b.id = p.blog_id
        JOIN users u ON u.id = b.user_id
        WHERE p.slug = %s
        AND p.published = TRUE
    """, (slug,))

    post_data = cur.fetchone()

    if not post_data:
        cur.close()
        conn.close()
        abort(404)

    cur.execute("""
        UPDATE posts
        SET views = views + 1
        WHERE id = %s
    """, (post_data["id"],))

    cur.execute("""
        INSERT INTO page_views
        (user_id, page_type, page_id)
        VALUES (%s, %s, %s)
    """, (
        None,
        "post",
        post_data["id"]
    ))

    conn.commit()

    cur.close()
    conn.close()

    return render_template(
        "blog.html",
        blog={
            "title": post_data["blog_title"],
            "description": ""
        },
        posts=[post_data]
    )


# ---------------------------------------------------------
# BUSINESS
# ---------------------------------------------------------

@app.route("/business/create", methods=["POST"])
@login_required
def create_business():

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    phone = request.form.get("phone", "").strip()
    whatsapp = request.form.get("whatsapp", "").strip()
    location = request.form.get("location", "").strip()
    website = request.form.get("website", "").strip()
    category = request.form.get("category", "").strip()

    if not name:
        flash("Business name is required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO businesses
        (
            user_id,
            name,
            description,
            phone,
            whatsapp,
            location,
            website,
            category
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        session["user_id"],
        name,
        description,
        phone,
        whatsapp,
        location,
        website,
        category
    ))

    conn.commit()

    cur.close()
    conn.close()

    flash("Your free business page has been created!", "success")

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# BUSINESS DIRECTORY
# ---------------------------------------------------------

@app.route("/businesses")
def businesses():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM businesses
        ORDER BY created_at DESC
        LIMIT 100
    """)

    business_list = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "business.html",
        businesses=business_list
    )


# ---------------------------------------------------------
# BUSINESS VIEW
# ---------------------------------------------------------

@app.route("/business/<int:business_id>")
def business(business_id):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM businesses
        WHERE id = %s
    """, (business_id,))

    business_data = cur.fetchone()

    if not business_data:
        cur.close()
        conn.close()
        abort(404)

    cur.execute("""
        UPDATE businesses
        SET views = views + 1
        WHERE id = %s
    """, (business_id,))

    cur.execute("""
        INSERT INTO page_views
        (page_type, page_id)
        VALUES (%s, %s)
    """, (
        "business",
        business_id
    ))

    conn.commit()

    cur.close()
    conn.close()

    return render_template(
        "business.html",
        businesses=[business_data]
    )


# ---------------------------------------------------------
# ADMIN
# ---------------------------------------------------------

@app.route("/admin")
@admin_required
def admin():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM users")
    users = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM blogs")
    blogs = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM posts")
    posts = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM businesses")
    businesses = cur.fetchone()["total"]

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM page_views
    """)

    views = cur.fetchone()["total"]

    cur.close()
    conn.close()

    return render_template(
        "admin.html",
        users=users,
        blogs=blogs,
        posts=posts,
        businesses=businesses,
        views=views
    )


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.route("/health")
def health():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()

        cur.close()
        conn.close()

        return {
            "status": "ok",
            "database": "connected",
            "app": "NijaWeber"
        }

    except Exception as e:
        return {
            "status": "error",
            "database": "not connected",
            "message": str(e)
        }, 500


# ---------------------------------------------------------
# STARTUP
# ---------------------------------------------------------

try:
    init_db()
except Exception as startup_error:
    print("Database initialization warning:", startup_error)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
