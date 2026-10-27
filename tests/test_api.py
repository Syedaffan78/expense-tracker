import os
import tempfile
import unittest
from pathlib import Path
from datetime import date

_test_database_dir = tempfile.TemporaryDirectory()
_previous_database = os.environ.get("EXPENSES_DATABASE")
os.environ["EXPENSES_DATABASE"] = str(
    Path(_test_database_dir.name) / "test-expenses.db"
)

import app as expense_app


class ExpenseApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = expense_app.app.test_client()

    @classmethod
    def tearDownClass(cls):
        _test_database_dir.cleanup()
        if _previous_database is None:
            os.environ.pop("EXPENSES_DATABASE", None)
        else:
            os.environ["EXPENSES_DATABASE"] = _previous_database

    def setUp(self):
        with expense_app.connect_db() as conn:
            conn.execute("DELETE FROM expenses")
            conn.execute("DELETE FROM budgets")
            self.category_id = conn.execute(
                "SELECT id FROM categories WHERE name = 'Food'"
            ).fetchone()["id"]

    def create_expense(self, **overrides):
        payload = {
            "amount": 125.50,
            "category_id": self.category_id,
            "date": "2026-10-12",
            "note": "Lunch",
        }
        payload.update(overrides)
        return self.client.post("/api/v1/expenses", json=payload)

    def test_expense_crud_and_filter(self):
        created = self.create_expense()
        self.assertEqual(created.status_code, 201)
        expense_id = created.json["data"]["id"]
        self.assertEqual(created.json["data"]["category"], "Food")

        updated = self.client.patch(
            f"/api/v1/expenses/{expense_id}", json={"note": "Dinner"}
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json["data"]["note"], "Dinner")

        listed = self.client.get(
            "/api/v1/expenses?start_date=2026-10-01&end_date=2026-10-31"
        )
        self.assertEqual(listed.json["pagination"]["total"], 1)
        self.assertEqual(listed.json["data"][0]["id"], expense_id)

        deleted = self.client.delete(f"/api/v1/expenses/{expense_id}")
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(
            self.client.get(f"/api/v1/expenses/{expense_id}").status_code, 404
        )

    def test_expense_validation_and_content_type(self):
        self.assertEqual(self.create_expense(amount=float("inf")).status_code, 400)
        self.assertEqual(self.create_expense(category_id=999999).status_code, 400)
        self.assertEqual(
            self.client.post("/api/v1/expenses", data="{}", content_type="text/plain").status_code,
            415,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/expenses", data="{", content_type="application/json"
            ).status_code,
            400,
        )

    def test_category_conflicts_with_existing_expenses(self):
        created = self.create_expense()
        category_id = created.json["data"]["category_id"]
        response = self.client.delete(f"/api/v1/categories/{category_id}")
        self.assertEqual(response.status_code, 409)

        duplicate = self.client.post(
            "/api/v1/categories", json={"name": "Food"}
        )
        self.assertEqual(duplicate.status_code, 409)

    def test_category_crud(self):
        created = self.client.post(
            "/api/v1/categories", json={"name": "Travel"}
        )
        self.assertEqual(created.status_code, 201)
        category_id = created.json["data"]["id"]

        updated = self.client.patch(
            f"/api/v1/categories/{category_id}", json={"name": "Trips"}
        )
        self.assertEqual(updated.json["data"]["name"], "Trips")
        self.assertEqual(
            self.client.delete(f"/api/v1/categories/{category_id}").status_code,
            204,
        )

    def test_budget_crud_reports_monthly_spending(self):
        self.create_expense()
        created = self.client.post(
            "/api/v1/budgets",
            json={
                "amount": 200,
                "month": "2026-10",
                "category_id": self.category_id,
            },
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json["data"]["spent"], 125.5)
        budget_id = created.json["data"]["id"]

        updated = self.client.patch(
            f"/api/v1/budgets/{budget_id}", json={"amount": 100}
        )
        self.assertEqual(updated.json["data"]["remaining"], -25.5)
        self.assertEqual(
            self.client.delete(f"/api/v1/budgets/{budget_id}").status_code, 204
        )

    def test_api_index_is_available(self):
        response = self.client.get("/api/v1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["version"], "1.0")

    def test_existing_html_pages_remain_available(self):
        for path in ("/", "/add", "/categories", "/budgets"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_dashboard_chart_refreshes_after_adding_expense(self):
        response = self.client.post("/add", data={
            "amount": "125.50",
            "category_id": str(self.category_id),
            "date": date.today().isoformat(),
            "note": "Lunch",
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        html = response.get_data(as_text=True)
        self.assertIn("data-category-values='[125.5, 0, 0, 0, 0, 0, 0, 0]'", html)
        self.assertIn(f"data-month-values='[125.5]'", html)

    def test_legacy_database_schema_supports_web_and_api_writes(self):
        original_database = expense_app.DATABASE
        legacy_database = Path(_test_database_dir.name) / "legacy-expenses.db"
        try:
            expense_app.DATABASE = legacy_database
            with expense_app.connect_db() as conn:
                conn.execute("""
                    CREATE TABLE categories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE
                    )
                """)
                conn.execute("""
                    CREATE TABLE expenses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        expense_date TEXT NOT NULL,
                        category_id INTEGER NOT NULL,
                        amount REAL NOT NULL,
                        note TEXT DEFAULT ''
                    )
                """)
                conn.execute("""
                    CREATE TABLE budgets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        month TEXT NOT NULL,
                        category_id INTEGER,
                        amount REAL NOT NULL
                    )
                """)
                conn.execute("INSERT INTO categories (name) VALUES ('Food')")
                conn.execute("""
                    INSERT INTO expenses (expense_date, category_id, amount, note)
                    VALUES ('2026-10-10', 1, 25, 'Legacy')
                """)

            expense_app.init_db()
            with expense_app.connect_db() as conn:
                migrated = conn.execute(
                    "SELECT date, expense_date FROM expenses WHERE id = 1"
                ).fetchone()
                self.assertEqual(migrated["date"], "2026-10-10")
                self.assertEqual(migrated["expense_date"], "2026-10-10")

            web_response = self.client.post("/add", data={
                "amount": "30",
                "category_id": "1",
                "date": "2026-10-11",
                "note": "Web",
            })
            self.assertEqual(web_response.status_code, 302)

            api_response = self.client.post("/api/v1/expenses", json={
                "amount": 40,
                "category_id": 1,
                "date": "2026-10-12",
                "note": "API",
            })
            self.assertEqual(api_response.status_code, 201)

            budget_response = self.client.post("/api/v1/budgets", json={
                "amount": 100,
                "month": "2026-10",
                "category_id": 1,
            })
            self.assertEqual(budget_response.status_code, 201)

            with expense_app.connect_db() as conn:
                dates = conn.execute("""
                    SELECT date, expense_date FROM expenses ORDER BY id
                """).fetchall()
                self.assertEqual(
                    [(row["date"], row["expense_date"]) for row in dates],
                    [
                        ("2026-10-10", "2026-10-10"),
                        ("2026-10-11", "2026-10-11"),
                        ("2026-10-12", "2026-10-12"),
                    ],
                )
        finally:
            expense_app.DATABASE = original_database


if __name__ == "__main__":
    unittest.main()
