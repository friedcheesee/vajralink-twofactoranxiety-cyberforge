def find_orders_by_customer(con, customer):
    return _query_orders(con, customer)


def _query_orders(con, customer):
    sql = "SELECT id, customer, total FROM orders WHERE customer = '%s'" % customer
    return con.execute(sql).fetchall()


def product_by_id_safe(con, pid):
    return con.execute("SELECT id, name FROM products WHERE id = ?", (pid,)).fetchone()
