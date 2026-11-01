"""Tiny deliberately-vulnerable web shop used ONLY to check that Vajra is not tuned to VulnerableApp.
Run:  .venv-win\\Scripts\\python.exe -m uvicorn app:app --app-dir scripts/unseen_app/shop --port 9300
Never expose it beyond localhost.
"""
import html
import os
import sqlite3
import subprocess

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from services import find_orders_by_customer, product_by_id_safe

app = FastAPI()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INVOICE_DIR = os.path.join(BASE_DIR, "invoices")
PAYMENT_API_KEY = "sk_live_51HxQe2Lk9dPq7Zr"  # planted: hard-coded secret
ALLOWED_RETURN = {"/", "/cart", "/orders"}


def _db():
    con = sqlite3.connect(os.path.join(BASE_DIR, "shop.db"))
    con.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    con.execute("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, customer TEXT, total REAL)")
    if not con.execute("SELECT COUNT(*) FROM products").fetchone()[0]:
        con.executemany("INSERT INTO products VALUES (?,?,?)", [(1, "Tea", 3.5), (2, "Coffee", 4.0)])
        con.executemany("INSERT INTO orders VALUES (?,?,?)", [(1, "alice", 10), (2, "bob", 20)])
        con.commit()
    return con


@app.get("/api/products/search", response_class=PlainTextResponse)
def search_products(name: str = ""):
    con = _db()
    rows = con.execute("SELECT id, name FROM products WHERE name = '" + name + "'").fetchall()  # planted: SQLi
    return "\n".join(f"{r[0]}:{r[1]}" for r in rows) or "no products"


@app.get("/api/products/{pid}", response_class=PlainTextResponse)
def get_product(pid: str):
    row = product_by_id_safe(_db(), pid)  # decoy: parameterised query
    return f"{row[0]}:{row[1]}" if row else "not found"


@app.get("/api/orders", response_class=PlainTextResponse)
def list_orders(customer: str = "alice"):
    rows = find_orders_by_customer(_db(), customer)  # planted: SQLi two calls deep
    return "\n".join(f"{r[0]}:{r[2]}" for r in rows) or "no orders"


@app.get("/search", response_class=HTMLResponse)
def search_page(q: str = ""):
    return "<html><body><h1>Results for " + q + "</h1></body></html>"  # planted: reflected XSS


@app.get("/review", response_class=HTMLResponse)
def review_page(text: str = ""):
    return "<html><body><p>" + html.escape(text) + "</p></body></html>"  # decoy: escaped output


@app.get("/api/shipping/ping", response_class=PlainTextResponse)
def ping_carrier(host: str = "127.0.0.1"):
    out = subprocess.run("echo pinging " + host, shell=True, capture_output=True, text=True)  # planted: command injection
    return out.stdout


@app.get("/api/invoice", response_class=PlainTextResponse)
def download_invoice(file: str = "inv1.txt"):
    with open(os.path.join(INVOICE_DIR, file), "r", errors="ignore") as fh:  # planted: path traversal
        return fh.read()


@app.get("/go")
def go(next: str = "/"):
    return RedirectResponse(next, status_code=302)  # planted: open redirect


@app.get("/back")
def back(next: str = "/"):
    target = next if next in ALLOWED_RETURN else "/"  # decoy: allow-listed redirect
    return RedirectResponse(target, status_code=302)
