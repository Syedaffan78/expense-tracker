from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, make_response, session, g
)
from werkzeug.exceptions import BadRequest
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
import csv
import io
import math
import os
import re
import secrets
import hmac
from contextlib import contextmanager
from datetime import datetime, date, timedelta
from pathlib import Path
from urllib.parse import urlsplit

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower()
    in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

DATABASE = Path(os.environ.get(
    "EXPENSES_DATABASE", Path(__file__).resolve().parent / "expenses.db"
))

DEFAULT_CATEGORIES = [
    "Food", "Transport", "Shopping", "Bills",
    "Education", "Health", "Entertainment", "Other"
]


# ==============================
# DATABASE
# ==============================

@contextmanager
def connect_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                amount REAL NOT NULL,
                category_id INTEGER NOT NULL,
                date TEXT,
                note TEXT DEFAULT '',
                user_id INTEGER,
                FOREIGN KEY (category_id) REFERENCES categories(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS budgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                amount REAL NOT NULL,
                month TEXT NOT NULL,
                category_id INTEGER,
                user_id INTEGER,
                FOREIGN KEY (category_id) REFERENCES categories(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Preserve existing data while adding missing columns.
        def columns(table):
            return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}

        cat_cols = columns("categories")
        exp_cols, bud_cols = columns("expenses"), columns("budgets")

        if "user_id" not in cat_cols:
            conn.execute("ALTER TABLE categories ADD COLUMN user_id INTEGER")
            conn.execute("""
                CREATE TABLE categories_scoped (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    user_id INTEGER
                )
            """)
            conn.execute("""
                INSERT INTO categories_scoped (id, name, user_id)
                SELECT id, name, user_id FROM categories
            """)
            conn.execute("DROP TABLE categories")
            conn.execute("ALTER TABLE categories_scoped RENAME TO categories")
        if "user_id" not in exp_cols:
            conn.execute("ALTER TABLE expenses ADD COLUMN user_id INTEGER")
        if "user_id" not in bud_cols:
            conn.execute("ALTER TABLE budgets ADD COLUMN user_id INTEGER")

        if "date" not in exp_cols:
            conn.execute("ALTER TABLE expenses ADD COLUMN date TEXT")
            exp_cols.add("date")
        if "note" not in exp_cols:
            conn.execute("ALTER TABLE expenses ADD COLUMN note TEXT DEFAULT ''")
        if "category_id" not in exp_cols:
            conn.execute("ALTER TABLE expenses ADD COLUMN category_id INTEGER")
        if "category_id" not in bud_cols:
            conn.execute("ALTER TABLE budgets ADD COLUMN category_id INTEGER")
        if "name" not in bud_cols:
            conn.execute(
                "ALTER TABLE budgets ADD COLUMN name TEXT NOT NULL DEFAULT 'Overall Budget'"
            )

        if "expense_date" in exp_cols:
            conn.execute("""
                UPDATE expenses SET date = expense_date
                WHERE (date IS NULL OR TRIM(date) = '')
                AND expense_date IS NOT NULL AND TRIM(expense_date) != ''
            """)

        conn.execute("""
            UPDATE expenses SET date = ?
            WHERE date IS NULL OR TRIM(date) = ''
        """, (date.today().isoformat(),))

        if "expense_date" in exp_cols:
            conn.execute("""
                UPDATE expenses SET expense_date = date
                WHERE expense_date IS NULL OR TRIM(expense_date) = ''
            """)

        if "name" not in bud_cols:
            conn.execute("""
                UPDATE budgets
                SET name = COALESCE(
                    (SELECT name FROM categories WHERE categories.id = budgets.category_id),
                    'Overall Budget'
                )
            """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_categories_user_name
            ON categories(user_id, name COLLATE NOCASE)
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_expenses_user ON expenses(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_budgets_user ON budgets(user_id)")

        first_user = conn.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if first_user is not None:
            user_id = first_user["id"]
            conn.execute("UPDATE categories SET user_id = ? WHERE user_id IS NULL", (user_id,))
            conn.execute("UPDATE expenses SET user_id = ? WHERE user_id IS NULL", (user_id,))
            conn.execute("UPDATE budgets SET user_id = ? WHERE user_id IS NULL", (user_id,))
            for category in DEFAULT_CATEGORIES:
                conn.execute(
                    "INSERT OR IGNORE INTO categories (name, user_id) VALUES (?, ?)",
                    (category, user_id),
                )


def create_account(conn, email, password):
    cursor = conn.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (email, generate_password_hash(password)),
    )
    user_id = cursor.lastrowid
    conn.execute(
        "UPDATE categories SET user_id = ? WHERE user_id IS NULL", (user_id,)
    )
    conn.execute("UPDATE expenses SET user_id = ? WHERE user_id IS NULL", (user_id,))
    conn.execute("UPDATE budgets SET user_id = ? WHERE user_id IS NULL", (user_id,))
    for category in DEFAULT_CATEGORIES:
        conn.execute(
            "INSERT OR IGNORE INTO categories (name, user_id) VALUES (?, ?)",
            (category, user_id),
        )
    return user_id


init_db()


# ==============================
# AUTHENTICATION
# ==============================

def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def has_account():
    with connect_db() as conn:
        return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def valid_csrf_token():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(submitted and expected and hmac.compare_digest(submitted, expected))


def safe_next_url(target):
    if not target:
        return None
    parsed = urlsplit(target)
    if (
        parsed.scheme or parsed.netloc or "\\" in target
        or not parsed.path.startswith("/") or parsed.path.startswith("//")
    ):
        return None
    return target


@app.before_request
def require_login():
    if request.endpoint is None or request.endpoint == "static":
        return None
    if request.endpoint in ("login", "setup", "register"):
        return None

    user_id = session.get("user_id")
    if user_id is not None:
        with connect_db() as conn:
            user = conn.execute(
                "SELECT id, email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if user is not None:
            g.current_user = user
            return None
        session.clear()

    destination = "login" if has_account() else "setup"
    if request.path.startswith("/api/"):
        return {"error": {"message": "Authentication required."}}, 401
    if destination == "login":
        return redirect(url_for(destination, next=request.full_path.rstrip("?")))
    return redirect(url_for(destination))


@app.after_request
def prevent_private_page_caching(response):
    endpoint = request.endpoint or ""
    if endpoint != "static" and not endpoint.startswith("api_"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if has_account():
        return redirect(url_for("login"))

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("setup"))

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        if (
            len(email) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        ):
            flash("Enter a valid email address.", "error")
        elif len(password) < 10:
            flash("Choose a password with at least 10 characters.", "error")
        elif len(password) > 1024:
            flash("Choose a shorter password.", "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        else:
            try:
                with connect_db() as conn:
                    create_account(conn, email, password)
            except sqlite3.IntegrityError:
                flash("An account already exists. Please sign in.", "error")
                return redirect(url_for("login"))

            session.clear()
            flash("Your account is ready. Sign in to continue.", "success")
            return redirect(url_for("login"))

    return render_template("setup.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id") is not None:
        return redirect(url_for("index"))

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("register"))

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        if (
            len(email) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        ):
            flash("Enter a valid email address.", "error")
        elif len(password) < 10:
            flash("Choose a password with at least 10 characters.", "error")
        elif len(password) > 1024:
            flash("Choose a shorter password.", "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        else:
            try:
                with connect_db() as conn:
                    user_id = create_account(conn, email, password)
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
            else:
                session.clear()
                session["user_id"] = user_id
                flash("Your private account is ready.", "success")
                return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not has_account():
        return redirect(url_for("setup"))
    if session.get("user_id") is not None:
        return redirect(url_for("index"))

    next_url = safe_next_url(
        request.form.get("next") if request.method == "POST"
        else request.args.get("next")
    )

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("login"))

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if len(password) > 1024:
            flash("Email or password is incorrect.", "error")
            return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

        with connect_db() as conn:
            user = conn.execute(
                "SELECT id, email, password_hash FROM users WHERE email = ?",
                (email,),
            ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Email or password is incorrect.", "error")
            return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        session.permanent = request.form.get("remember") == "on"
        return redirect(next_url or url_for("index"))

    return render_template("login.html", next_url=next_url)


@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf_token():
        flash("Your session expired. Please try again.", "error")
        return redirect(url_for("index"))
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


# ==============================
# TEMPLATE HELPERS
# ==============================

@app.template_filter("money")
def money(value):
    try:
        return f"₹{float(value or 0):,.2f}"
    except (TypeError, ValueError):
        return "₹0.00"


def current_user_id():
    return g.current_user["id"]


def get_categories():
    with connect_db() as conn:
        return conn.execute(
            "SELECT * FROM categories WHERE user_id = ? ORDER BY name",
            (current_user_id(),),
        ).fetchall()


def insert_expense(conn, expense):
    date_columns = ["date"]
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(expenses)")}
    if "expense_date" in columns:
        date_columns.append("expense_date")
    date_placeholders = ", ".join("?" for _ in date_columns)
    cursor = conn.execute(
        f"""
        INSERT INTO expenses (
            amount, category_id, {', '.join(date_columns)}, note, user_id
        )
        VALUES (?, ?, {date_placeholders}, ?, ?)
        """,
        (
            expense["amount"], expense["category_id"],
            *[expense["date"] for _ in date_columns], expense["note"],
            current_user_id(),
        ),
    )
    return cursor.lastrowid


def update_expense(conn, expense, expense_id):
    date_columns = ["date"]
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(expenses)")}
    if "expense_date" in columns:
        date_columns.append("expense_date")
    date_assignments = ", ".join(f"{column} = ?" for column in date_columns)
    conn.execute(
        f"""
        UPDATE expenses
        SET amount = ?, category_id = ?, {date_assignments}, note = ?
        WHERE id = ? AND user_id = ?
        """,
        (
            expense["amount"], expense["category_id"],
            *[expense["date"] for _ in date_columns], expense["note"], expense_id,
            current_user_id(),
        ),
    )


def validate_expense_form():
    amount_text = request.form.get("amount", "").strip()
    category_text = request.form.get("category_id", "").strip()
    expense_date = request.form.get("date", "").strip()
    note = request.form.get("note", "").strip()

    try:
        amount = float(amount_text)
        if amount <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return None, "Enter a valid amount greater than zero."

    try:
        category_id = int(category_text)
    except (ValueError, TypeError):
        return None, "Please select a category."

    with connect_db() as conn:
        category = conn.execute(
            "SELECT id FROM categories WHERE id = ? AND user_id = ?",
            (category_id, current_user_id()),
        ).fetchone()

    if category is None:
        return None, "The selected category does not exist."

    try:
        parsed_date = datetime.strptime(expense_date, "%Y-%m-%d").date()
        if parsed_date.isoformat() != expense_date:
            raise ValueError
    except (ValueError, TypeError):
        return None, "Please select a valid date using the calendar."

    return {
        "amount": amount,
        "category_id": category_id,
        "date": parsed_date.isoformat(),
        "note": note,
    }, None


# ==============================
# DASHBOARD
# ==============================

@app.route("/")
def index():
    today = date.today()
    current_month = today.strftime("%Y-%m")

    filters = {
        "search": request.args.get("search", "").strip(),
        "category": request.args.get("category", "").strip(),
        "date": request.args.get("date", "").strip(),
    }

    with connect_db() as conn:
        all_expenses = conn.execute("""
            SELECT expenses.*, categories.name AS category_name
            FROM expenses
            LEFT JOIN categories ON expenses.category_id = categories.id
            WHERE expenses.user_id = ?
            ORDER BY expenses.date ASC, expenses.id ASC
        """, (current_user_id(),)).fetchall()

        total = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE user_id = ?",
            (current_user_id(),),
        ).fetchone()[0]

        today_total = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE date = ? AND user_id = ?",
            (today.isoformat(), current_user_id()),
        ).fetchone()[0]

        month_total = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM expenses
            WHERE substr(date, 1, 7) = ? AND user_id = ?
        """, (current_month, current_user_id())).fetchone()[0]

        highest = conn.execute(
            "SELECT COALESCE(MAX(amount), 0) FROM expenses WHERE user_id = ?",
            (current_user_id(),),
        ).fetchone()[0]

        category_totals = conn.execute("""
            SELECT categories.name AS name,
                   COALESCE(SUM(expenses.amount), 0) AS total
            FROM categories
            LEFT JOIN expenses
                ON categories.id = expenses.category_id
                AND substr(expenses.date, 1, 7) = ?
                AND expenses.user_id = ?
            WHERE categories.user_id = ?
            GROUP BY categories.id, categories.name
            ORDER BY total DESC
        """, (current_month, current_user_id(), current_user_id())).fetchall()

        monthly = conn.execute("""
            SELECT substr(date, 1, 7) AS month, SUM(amount) AS total
            FROM expenses
            WHERE date >= date('now', 'localtime', 'start of month', '-5 months')
                AND user_id = ?
            GROUP BY substr(date, 1, 7)
            ORDER BY month
        """, (current_user_id(),)).fetchall()

        overall_budget = conn.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM budgets
            WHERE month = ? AND category_id IS NULL AND user_id = ?
        """, (current_month, current_user_id())).fetchone()[0]

        category_budgets = conn.execute("""
            SELECT budgets.*, categories.name AS category_name
            FROM budgets
            LEFT JOIN categories ON budgets.category_id = categories.id
            WHERE budgets.month = ? AND budgets.user_id = ?
            ORDER BY budgets.id DESC
        """, (current_month, current_user_id())).fetchall()

    # Apply dashboard filters without changing stored expenses.
    expenses = list(all_expenses)

    if filters["search"]:
        term = filters["search"].casefold()
        expenses = [
            e for e in expenses
            if term in (e["note"] or "").casefold()
            or term in (e["category_name"] or "").casefold()
        ]

    if filters["category"]:
        try:
            cat_id = int(filters["category"])
            expenses = [e for e in expenses if e["category_id"] == cat_id]
        except ValueError:
            expenses = []

    if filters["date"]:
        try:
            filter_date = datetime.strptime(
                filters["date"], "%Y-%m-%d"
            ).date().isoformat()
            expenses = [e for e in expenses if e["date"] == filter_date]
        except ValueError:
            flash("The filter date is invalid.", "error")
            filters["date"] = ""

    response = make_response(render_template(
        "index.html",
        expenses=expenses,
        categories=get_categories(),
        total=total,
        today_total=today_total,
        month_total=month_total,
        highest=highest,
        category_totals=category_totals,
        monthly=monthly,
        overall_budget=overall_budget,
        category_budgets=category_budgets,
        current_month=current_month,
        selected_category=filters["category"],
        selected_date=filters["date"],
        filters=filters,
    ))
    response.headers["Cache-Control"] = "no-store"
    return response


# ==============================
# ADD EXPENSE
# ==============================

@app.route("/add", methods=["GET", "POST"])
def add_expense():
    if request.method == "POST":
        expense, error = validate_expense_form()

        if error:
            flash(error, "error")
            return redirect(url_for("add_expense"))

        with connect_db() as conn:
            insert_expense(conn, expense)

        flash("Expense added successfully!", "success")
        return redirect(url_for("index"))

    return render_template("add_expense.html", categories=get_categories())


# ==============================
# EDIT EXPENSE
# ==============================

@app.route("/edit/<int:expense_id>", methods=["GET", "POST"])
def edit_expense(expense_id):
    with connect_db() as conn:
        expense = conn.execute(
            "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, current_user_id()),
        ).fetchone()

    if expense is None:
        flash("Expense not found.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        updated, error = validate_expense_form()

        if error:
            flash(error, "error")
            return redirect(url_for("edit_expense", expense_id=expense_id))

        with connect_db() as conn:
            update_expense(conn, updated, expense_id)

        flash("Expense updated successfully!", "success")
        return redirect(url_for("index"))

    return render_template(
        "edit_expense.html", expense=expense, categories=get_categories()
    )


# ==============================
# DELETE EXPENSES
# ==============================

@app.route("/delete/<int:expense_id>", methods=["POST"])
def delete_expense(expense_id):
    with connect_db() as conn:
        conn.execute(
            "DELETE FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, current_user_id()),
        )

    flash("Expense deleted.", "success")
    return redirect(url_for("index"))


@app.route("/delete-all", methods=["POST"])
def delete_all():
    with connect_db() as conn:
        conn.execute("DELETE FROM expenses WHERE user_id = ?", (current_user_id(),))

    flash("All expenses deleted.", "success")
    return redirect(url_for("index"))


# ==============================
# CATEGORIES
# ==============================

@app.route("/categories", methods=["GET", "POST"])
def categories():
    if request.method == "POST":
        name = request.form.get("name", "").strip()

        if not name:
            flash("Enter a category name.", "error")
        else:
            try:
                with connect_db() as conn:
                    conn.execute(
                        "INSERT INTO categories (name, user_id) VALUES (?, ?)",
                        (name, current_user_id()),
                    )
                flash("Category added successfully!", "success")
            except sqlite3.IntegrityError:
                flash("That category already exists.", "error")

        return redirect(url_for("categories"))

    return render_template("categories.html", categories=get_categories())


@app.route("/categories/delete/<int:category_id>", methods=["POST"])
def delete_category(category_id):
    with connect_db() as conn:
        used = conn.execute(
            "SELECT COUNT(*) FROM expenses WHERE category_id = ? AND user_id = ?",
            (category_id, current_user_id()),
        ).fetchone()[0]

        if used:
            flash("Cannot delete a category that has existing expenses.", "error")
            return redirect(url_for("categories"))

        conn.execute(
            "DELETE FROM budgets WHERE category_id = ? AND user_id = ?",
            (category_id, current_user_id()),
        )
        conn.execute(
            "DELETE FROM categories WHERE id = ? AND user_id = ?",
            (category_id, current_user_id()),
        )

    flash("Category deleted.", "success")
    return redirect(url_for("categories"))


# ==============================
# BUDGETS
# ==============================

@app.route("/budgets", methods=["GET", "POST"])
def budgets():
    if request.method == "POST":
        amount_text = request.form.get("amount", "").strip()
        month = request.form.get("month", "").strip()
        category_text = request.form.get("category_id", "").strip()

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except (ValueError, TypeError):
            flash("Enter a valid budget amount.", "error")
            return redirect(url_for("budgets"))

        try:
            if datetime.strptime(month, "%Y-%m").strftime("%Y-%m") != month:
                raise ValueError
        except (ValueError, TypeError):
            flash("Select a valid budget month.", "error")
            return redirect(url_for("budgets"))

        category_id = None
        budget_name = "Overall Budget"

        if category_text:
            try:
                category_id = int(category_text)
            except ValueError:
                flash("Select a valid category.", "error")
                return redirect(url_for("budgets"))

            with connect_db() as conn:
                category = conn.execute(
                    "SELECT name FROM categories WHERE id = ? AND user_id = ?",
                    (category_id, current_user_id()),
                ).fetchone()

            if category is None:
                flash("The selected category does not exist.", "error")
                return redirect(url_for("budgets"))

            budget_name = category["name"]

        with connect_db() as conn:
            conn.execute("""
                INSERT INTO budgets (name, amount, month, category_id, user_id)
                VALUES (?, ?, ?, ?, ?)
            """, (budget_name, amount, month, category_id, current_user_id()))

        flash("Budget saved successfully!", "success")
        return redirect(url_for("budgets"))

    with connect_db() as conn:
        budget_list = conn.execute("""
            SELECT budgets.*, categories.name AS category_name
            FROM budgets
            LEFT JOIN categories ON budgets.category_id = categories.id
            WHERE budgets.user_id = ?
            ORDER BY budgets.month DESC, budgets.id DESC
        """, (current_user_id(),)).fetchall()

    return render_template(
        "budgets.html",
        budgets=budget_list,
        categories=get_categories(),
        current_month=date.today().strftime("%Y-%m"),
    )


@app.route("/budgets/delete/<int:budget_id>", methods=["POST"])
def delete_budget(budget_id):
    with connect_db() as conn:
        conn.execute(
            "DELETE FROM budgets WHERE id = ? AND user_id = ?",
            (budget_id, current_user_id()),
        )

    flash("Budget deleted.", "success")
    return redirect(url_for("budgets"))


# ==============================
# CSV EXPORT
# ==============================

@app.route("/export")
def export_expenses():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Amount", "Category", "Date", "Note"])

    with connect_db() as conn:
        rows = conn.execute("""
            SELECT expenses.id, expenses.amount,
                   categories.name AS category_name,
                   expenses.date, expenses.note
            FROM expenses
            LEFT JOIN categories ON expenses.category_id = categories.id
            WHERE expenses.user_id = ?
            ORDER BY expenses.date DESC
        """, (current_user_id(),)).fetchall()

    for r in rows:
        writer.writerow([
            r["id"], r["amount"], r["category_name"] or "Unknown",
            r["date"], r["note"] or "",
        ])

    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=expenses.csv"
    return response


# ==============================
# VERSIONED JSON API
# ==============================

def api_error(message, status, field=None):
    error = {"message": message}
    if field:
        error["field"] = field
    return {"error": error}, status


def api_json_object():
    if not request.is_json:
        return None, api_error("Request body must be JSON.", 415)
    try:
        payload = request.get_json()
    except BadRequest:
        return None, api_error("Request body contains invalid JSON.", 400)
    if not isinstance(payload, dict):
        return None, api_error("Request body must be a JSON object.", 400)
    return payload, None


def api_positive_amount(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        numeric_value = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(numeric_value) and 0 < numeric_value <= 999999999


def api_valid_date(value):
    if not isinstance(value, str):
        return False
    try:
        return datetime.strptime(value, "%Y-%m-%d").date().isoformat() == value
    except ValueError:
        return False


def api_valid_month(value):
    if not isinstance(value, str):
        return False
    try:
        return datetime.strptime(value, "%Y-%m").strftime("%Y-%m") == value
    except ValueError:
        return False


def api_expense_payload(payload, current=None):
    if not payload:
        return None, api_error("Provide at least one expense field.", 400)
    allowed = {"amount", "category_id", "date", "note"}
    unknown = set(payload) - allowed
    if unknown:
        return None, api_error(
            f"Unknown field: {sorted(unknown)[0]}.", 400, sorted(unknown)[0]
        )

    values = dict(current or {})
    values.update(payload)
    required = {"amount", "category_id", "date"}
    missing = required - values.keys()
    if missing:
        field = sorted(missing)[0]
        return None, api_error(f"'{field}' is required.", 400, field)

    if not api_positive_amount(values["amount"]):
        return None, api_error("Amount must be a finite number greater than zero.", 400, "amount")
    category_id = values["category_id"]
    if not isinstance(category_id, int) or isinstance(category_id, bool) or category_id <= 0:
        return None, api_error("Category ID must be a positive integer.", 400, "category_id")
    if not api_valid_date(values["date"]):
        return None, api_error("Date must use YYYY-MM-DD format.", 400, "date")
    note = values.get("note", "")
    if not isinstance(note, str):
        return None, api_error("Note must be a string.", 400, "note")
    return {
        "amount": float(values["amount"]),
        "category_id": category_id,
        "date": values["date"],
        "note": note.strip(),
    }, None


def api_expense_row(row):
    return {
        "id": row["id"],
        "amount": row["amount"],
        "category_id": row["category_id"],
        "category": row["category_name"],
        "date": row["date"],
        "note": row["note"] or "",
    }


def api_get_expense(conn, expense_id):
    return conn.execute("""
        SELECT expenses.*, categories.name AS category_name
        FROM expenses
        LEFT JOIN categories ON expenses.category_id = categories.id
        WHERE expenses.id = ? AND expenses.user_id = ?
    """, (expense_id, current_user_id())).fetchone()


def api_budget_row(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "amount": row["amount"],
        "month": row["month"],
        "category_id": row["category_id"],
        "category": row["category_name"],
        "spent": row["spent"],
        "remaining": row["amount"] - row["spent"],
    }


def api_budget_payload(payload, current=None):
    if not payload:
        return None, api_error("Provide at least one budget field.", 400)
    allowed = {"amount", "month", "category_id"}
    unknown = set(payload) - allowed
    if unknown:
        field = sorted(unknown)[0]
        return None, api_error(f"Unknown field: {field}.", 400, field)

    values = dict(current or {})
    values.update(payload)
    for field in ("amount", "month", "category_id"):
        if field not in values:
            return None, api_error(f"'{field}' is required.", 400, field)

    if not api_positive_amount(values["amount"]):
        return None, api_error("Amount must be a finite number greater than zero.", 400, "amount")
    if not api_valid_month(values["month"]):
        return None, api_error("Month must use YYYY-MM format.", 400, "month")
    category_id = values["category_id"]
    if category_id is not None and (
        not isinstance(category_id, int)
        or isinstance(category_id, bool)
        or category_id <= 0
    ):
        return None, api_error("Category ID must be a positive integer or null.", 400, "category_id")
    return {
        "amount": float(values["amount"]),
        "month": values["month"],
        "category_id": category_id,
    }, None


@app.route("/api/v1", methods=["GET"])
def api_v1():
    return {
        "name": "Expense Tracker API",
        "version": "1.0",
        "endpoints": {
            "expenses": "/api/v1/expenses",
            "categories": "/api/v1/categories",
            "budgets": "/api/v1/budgets",
        },
    }


@app.route("/api/v1/expenses", methods=["GET", "POST"])
def api_expenses():
    if request.method == "POST":
        payload, error = api_json_object()
        if error:
            return error
        values, error = api_expense_payload(payload)
        if error:
            return error
        with connect_db() as conn:
            category = conn.execute(
                "SELECT id FROM categories WHERE id = ? AND user_id = ?",
                (values["category_id"], current_user_id()),
            ).fetchone()
            if category is None:
                return api_error("Category does not exist.", 400, "category_id")
            expense_id = insert_expense(conn, values)
            row = api_get_expense(conn, expense_id)
            result = api_expense_row(row)
        return {"data": result}, 201, {"Location": url_for("api_expense", expense_id=result["id"])}

    filters = {}
    for field in ("start_date", "end_date"):
        value = request.args.get(field)
        if value and not api_valid_date(value):
            return api_error(f"{field} must use YYYY-MM-DD format.", 400, field)
        if value:
            filters[field] = value
    if (
        "start_date" in filters
        and "end_date" in filters
        and filters["start_date"] > filters["end_date"]
    ):
        return api_error("start_date must be on or before end_date.", 400, "start_date")
    category_id = request.args.get("category_id")
    if category_id:
        try:
            filters["category_id"] = int(category_id)
            if filters["category_id"] <= 0:
                raise ValueError
        except ValueError:
            return api_error("Category ID must be a positive integer.", 400, "category_id")
    search = request.args.get("search", "").strip()
    try:
        limit = int(request.args.get("limit", "50"))
        offset = int(request.args.get("offset", "0"))
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError
    except ValueError:
        return api_error("Limit must be 1-100 and offset must be zero or greater.", 400)

    clauses, params = ["expenses.user_id = ?"], [current_user_id()]
    if "category_id" in filters:
        clauses.append("expenses.category_id = ?")
        params.append(filters["category_id"])
    if "start_date" in filters:
        clauses.append("expenses.date >= ?")
        params.append(filters["start_date"])
    if "end_date" in filters:
        clauses.append("expenses.date <= ?")
        params.append(filters["end_date"])
    if search:
        clauses.append("(expenses.note LIKE ? OR categories.name LIKE ?)")
        params.extend((f"%{search}%", f"%{search}%"))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect_db() as conn:
        total = conn.execute(f"""
            SELECT COUNT(*)
            FROM expenses
            LEFT JOIN categories ON expenses.category_id = categories.id
            {where}
        """, params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT expenses.*, categories.name AS category_name
            FROM expenses
            LEFT JOIN categories ON expenses.category_id = categories.id
            {where}
            ORDER BY expenses.date DESC, expenses.id DESC
            LIMIT ? OFFSET ?
        """, (*params, limit, offset)).fetchall()
    return {
        "data": [api_expense_row(row) for row in rows],
        "pagination": {"limit": limit, "offset": offset, "total": total},
    }


@app.route("/api/v1/expenses/<int:expense_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
def api_expense(expense_id):
    with connect_db() as conn:
        row = api_get_expense(conn, expense_id)
        if row is None:
            return api_error("Expense not found.", 404)
        if request.method == "GET":
            return {"data": api_expense_row(row)}
        if request.method == "DELETE":
            conn.execute(
                "DELETE FROM expenses WHERE id = ? AND user_id = ?",
                (expense_id, current_user_id()),
            )
            return "", 204

        payload, error = api_json_object()
        if error:
            return error
        current = {
            "amount": row["amount"],
            "category_id": row["category_id"],
            "date": row["date"],
            "note": row["note"] or "",
        }
        values, error = api_expense_payload(
            payload, current if request.method == "PATCH" else None
        )
        if error:
            return error
        category = conn.execute(
            "SELECT id FROM categories WHERE id = ? AND user_id = ?",
            (values["category_id"], current_user_id()),
        ).fetchone()
        if category is None:
            return api_error("Category does not exist.", 400, "category_id")
        update_expense(conn, values, expense_id)
        updated = api_get_expense(conn, expense_id)
        return {"data": api_expense_row(updated)}


@app.route("/api/v1/categories", methods=["GET", "POST"])
def api_categories():
    if request.method == "POST":
        payload, error = api_json_object()
        if error:
            return error
        if set(payload) != {"name"}:
            return api_error("Provide only the 'name' field.", 400, "name")
        name = payload["name"]
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 50:
            return api_error("Name must contain 1-50 characters.", 400, "name")
        try:
            with connect_db() as conn:
                cursor = conn.execute(
                    "INSERT INTO categories (name, user_id) VALUES (?, ?)",
                    (name.strip(), current_user_id()),
                )
                category = conn.execute(
                    "SELECT id, name FROM categories WHERE id = ? AND user_id = ?",
                    (cursor.lastrowid, current_user_id()),
                ).fetchone()
        except sqlite3.IntegrityError:
            return api_error("Category already exists.", 409, "name")
        result = dict(category)
        return {"data": result}, 201, {"Location": url_for("api_category", category_id=result["id"])}

    with connect_db() as conn:
        rows = conn.execute("""
            SELECT categories.id, categories.name, COUNT(expenses.id) AS expense_count
            FROM categories
            LEFT JOIN expenses ON expenses.category_id = categories.id
                AND expenses.user_id = ?
            WHERE categories.user_id = ?
            GROUP BY categories.id, categories.name
            ORDER BY categories.name
        """, (current_user_id(), current_user_id())).fetchall()
    return {"data": [dict(row) for row in rows]}


@app.route("/api/v1/categories/<int:category_id>", methods=["GET", "PATCH", "DELETE"])
def api_category(category_id):
    with connect_db() as conn:
        row = conn.execute(
            "SELECT id, name FROM categories WHERE id = ? AND user_id = ?",
            (category_id, current_user_id()),
        ).fetchone()
        if row is None:
            return api_error("Category not found.", 404)
        if request.method == "GET":
            return {"data": dict(row)}
        if request.method == "DELETE":
            used = conn.execute(
                "SELECT COUNT(*) FROM expenses WHERE category_id = ? AND user_id = ?",
                (category_id, current_user_id()),
            ).fetchone()[0]
            if used:
                return api_error("Cannot delete a category used by expenses.", 409)
            conn.execute(
                "DELETE FROM budgets WHERE category_id = ? AND user_id = ?",
                (category_id, current_user_id()),
            )
            conn.execute(
                "DELETE FROM categories WHERE id = ? AND user_id = ?",
                (category_id, current_user_id()),
            )
            return "", 204

        payload, error = api_json_object()
        if error:
            return error
        if set(payload) != {"name"}:
            return api_error("Provide only the 'name' field.", 400, "name")
        name = payload["name"]
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 50:
            return api_error("Name must contain 1-50 characters.", 400, "name")
        try:
            conn.execute(
                "UPDATE categories SET name = ? WHERE id = ? AND user_id = ?",
                (name.strip(), category_id, current_user_id()),
            )
        except sqlite3.IntegrityError:
            return api_error("Category already exists.", 409, "name")
        updated = conn.execute(
            "SELECT id, name FROM categories WHERE id = ? AND user_id = ?",
            (category_id, current_user_id()),
        ).fetchone()
        return {"data": dict(updated)}


@app.route("/api/v1/budgets", methods=["GET", "POST"])
def api_budgets():
    if request.method == "POST":
        payload, error = api_json_object()
        if error:
            return error
        values, error = api_budget_payload(payload)
        if error:
            return error
        with connect_db() as conn:
            category_name = None
            if values["category_id"] is not None:
                category = conn.execute(
                    "SELECT name FROM categories WHERE id = ? AND user_id = ?",
                    (values["category_id"], current_user_id()),
                ).fetchone()
                if category is None:
                    return api_error("Category does not exist.", 400, "category_id")
                category_name = category["name"]
            cursor = conn.execute("""
                INSERT INTO budgets (name, amount, month, category_id, user_id)
                VALUES (?, ?, ?, ?, ?)
            """, (
                category_name or "Overall Budget",
                values["amount"], values["month"], values["category_id"],
                current_user_id(),
            ))
            row = conn.execute("""
                SELECT budgets.*, categories.name AS category_name,
                       COALESCE((
                           SELECT SUM(expenses.amount) FROM expenses
                           WHERE substr(expenses.date, 1, 7) = budgets.month
                           AND expenses.user_id = budgets.user_id
                           AND (budgets.category_id IS NULL
                                OR expenses.category_id = budgets.category_id)
                       ), 0) AS spent
                FROM budgets
                LEFT JOIN categories ON categories.id = budgets.category_id
                WHERE budgets.id = ? AND budgets.user_id = ?
            """, (cursor.lastrowid, current_user_id())).fetchone()
        result = api_budget_row(row)
        return {"data": result}, 201, {"Location": url_for("api_budget", budget_id=result["id"])}

    month = request.args.get("month")
    if month and not api_valid_month(month):
        return api_error("Month must use YYYY-MM format.", 400, "month")
    query = """
        SELECT budgets.*, categories.name AS category_name,
               COALESCE((
                   SELECT SUM(expenses.amount) FROM expenses
                   WHERE substr(expenses.date, 1, 7) = budgets.month
                   AND expenses.user_id = budgets.user_id
                   AND (budgets.category_id IS NULL
                        OR expenses.category_id = budgets.category_id)
               ), 0) AS spent
        FROM budgets
        LEFT JOIN categories ON categories.id = budgets.category_id
        WHERE budgets.user_id = ?
    """
    params = [current_user_id()]
    if month:
        query += " AND budgets.month = ?"
        params.append(month)
    query += " ORDER BY budgets.month DESC, budgets.id DESC"
    with connect_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return {"data": [api_budget_row(row) for row in rows]}


@app.route("/api/v1/budgets/<int:budget_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
def api_budget(budget_id):
    with connect_db() as conn:
        row = conn.execute("""
            SELECT budgets.*, categories.name AS category_name
            FROM budgets
            LEFT JOIN categories ON categories.id = budgets.category_id
            WHERE budgets.id = ? AND budgets.user_id = ?
        """, (budget_id, current_user_id())).fetchone()
        if row is None:
            return api_error("Budget not found.", 404)
        if request.method == "GET":
            budget = conn.execute("""
                SELECT budgets.*, categories.name AS category_name,
                       COALESCE((
                           SELECT SUM(expenses.amount) FROM expenses
                           WHERE substr(expenses.date, 1, 7) = budgets.month
                           AND expenses.user_id = budgets.user_id
                           AND (budgets.category_id IS NULL
                                OR expenses.category_id = budgets.category_id)
                       ), 0) AS spent
                FROM budgets
                LEFT JOIN categories ON categories.id = budgets.category_id
                WHERE budgets.id = ? AND budgets.user_id = ?
            """, (budget_id, current_user_id())).fetchone()
            return {"data": api_budget_row(budget)}
        if request.method == "DELETE":
            conn.execute(
                "DELETE FROM budgets WHERE id = ? AND user_id = ?",
                (budget_id, current_user_id()),
            )
            return "", 204

        payload, error = api_json_object()
        if error:
            return error
        current = {
            "amount": row["amount"],
            "month": row["month"],
            "category_id": row["category_id"],
        }
        values, error = api_budget_payload(
            payload, current if request.method == "PATCH" else None
        )
        if error:
            return error
        category_name = None
        if values["category_id"] is not None:
            category = conn.execute(
                "SELECT name FROM categories WHERE id = ? AND user_id = ?",
                (values["category_id"], current_user_id()),
            ).fetchone()
            if category is None:
                return api_error("Category does not exist.", 400, "category_id")
            category_name = category["name"]
        conn.execute("""
            UPDATE budgets SET name = ?, amount = ?, month = ?, category_id = ?
            WHERE id = ? AND user_id = ?
        """, (
            category_name or "Overall Budget",
            values["amount"], values["month"], values["category_id"], budget_id,
            current_user_id(),
        ))
        updated = conn.execute("""
            SELECT budgets.*, categories.name AS category_name,
                   COALESCE((
                       SELECT SUM(expenses.amount) FROM expenses
                       WHERE substr(expenses.date, 1, 7) = budgets.month
                       AND expenses.user_id = budgets.user_id
                       AND (budgets.category_id IS NULL
                            OR expenses.category_id = budgets.category_id)
                   ), 0) AS spent
            FROM budgets
            LEFT JOIN categories ON categories.id = budgets.category_id
            WHERE budgets.id = ? AND budgets.user_id = ?
        """, (budget_id, current_user_id())).fetchone()
        return {"data": api_budget_row(updated)}


# Compatibility endpoint for templates using the older name.
app.add_url_rule(
    "/export", endpoint="export_csv",
    view_func=export_expenses, methods=["GET"]
)


# ==============================
# RUN APP
# ==============================

if __name__ == "__main__":
    app.run(debug=True)