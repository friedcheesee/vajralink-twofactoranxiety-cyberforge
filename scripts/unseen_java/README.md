# unseen_java: Pagecraft Books (local test fixture)

A small Spring Boot 3 / H2 bookstore with deliberately planted, textbook bugs. It exists only to check that
VajraLink generalises beyond the organizers' VulnerableApp. Never deploy it. It binds to 127.0.0.1 by
default (inside Docker it binds 0.0.0.0, and you must publish the port to loopback only).

Build and run (Docker, port 9400):

    docker build -t vajra-unseen-bookshop -f scripts/unseen_java/Dockerfile scripts/unseen_java/bookshop
    docker run --rm -d --name vajra-bookshop -p 127.0.0.1:9400:9400 vajra-unseen-bookshop

Evaluate (from the repo root):

    .venv-win\Scripts\python.exe scripts\unseen_java\eval_unseen_java.py http://127.0.0.1:9400
    docker stop vajra-bookshop

The scorer takes optional `--key` and `--target`; `answer_key.json` uses the same schema as
`scripts/unseen_app/answer_key.json` (file paths relative to the app source root, exact sink lines).

| URL | Planted |
|---|---|
| GET /catalog/search?term= | CWE-89 in controller (string-built Statement) |
| GET /api/orders/{orderId} | CWE-89 reached through OrderService (DI) |
| GET /reviews/preview?comment= | CWE-79 raw String response |
| POST /api/shipping/trace (JSON `host`) | CWE-78 `sh -c ping` |
| GET /account/avatar?name= | CWE-22 |
| GET /checkout/return?next= | CWE-601 |
| GET /catalog/title?isbn= | decoy: PreparedStatement |
| POST /feedback/submit (form `message`) | decoy: HtmlUtils.htmlEscape |
| GET /checkout/continue?next= | decoy: redirect allow-list |
| GET /catalog/featured, /status, / | benign |
| (GatewayClient.java) | CWE-798 hard-coded secret, code-only |
| (all responses) | missing security headers, runtime-only |
