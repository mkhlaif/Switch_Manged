"""Read-only integrations with external systems (NetBox, Zabbix).

Both clients are READ-ONLY by construction: they expose no method that could write, the HTTP
verb / JSON-RPC method is checked against a small allowlist before every request, and the
application never changes NetBox or Zabbix automatically.
"""
