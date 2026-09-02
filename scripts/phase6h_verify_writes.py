from pathlib import Path
import sqlite3

from sqlalchemy import text

from app.db.session import SessionLocal

db = SessionLocal()
asset = db.execute(text("select id, name from hardware_assets where name like 'Phase 6H HTTP asset updated%' order by id desc limit 1")).mappings().first()
print("postgres-asset", dict(asset) if asset else None)
db.close()
connection = sqlite3.connect(Path("/app/data/kaya.db"))
row = connection.execute("select id, name from hardware_assets where name like 'Phase 6H HTTP asset updated%' order by id desc limit 1").fetchone()
print("sqlite-asset", row)
connection.close()
