import sqlite3
from pathlib import Path

DATABASE = Path(__file__).resolve().parent / "expenses.db"

connection = sqlite3.connect(DATABASE)
connection.row_factory = sqlite3.Row

try:
    # Inspect the existing expenses table
    columns = connection.execute(
        "PRAGMA table_info(expenses)"
    ).fetchall()

    print("Existing expenses columns:")
    for column in columns:
        print(f"- {column['name']} ({column['type']})")

    column_names = [column["name"] for column in columns]

    if not columns:
        print("\nThe expenses table does not exist.")
        print("Start app.py to create the tables.")
    else:
        # Add the date column if missing
        if "date" not in column_names:
            connection.execute(
                "ALTER TABLE expenses ADD COLUMN date TEXT"
            )
            print("\nAdded missing date column.")

            # Preserve existing expenses and give them today's date.
            from datetime import date

            connection.execute(
                """
                UPDATE expenses
                SET date = ?
                WHERE date IS NULL OR TRIM(date) = ''
                """,
                (date.today().isoformat(),),
            )
            print("Assigned today's date to old expenses.")

        # Check the note column
        if "note" not in column_names:
            connection.execute(
                "ALTER TABLE expenses ADD COLUMN note TEXT DEFAULT ''"
            )
            print("Added missing note column.")

        connection.commit()
        print("\nDatabase repair completed.")

except sqlite3.Error as error:
    connection.rollback()
    print(f"\nDatabase repair failed: {error}")

finally:
    connection.close()