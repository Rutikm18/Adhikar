"""ASGI entry point.

Application composition lives in ``app.factory`` and HTTP transport in
``app.api`` so tests can create isolated app instances without global rewiring.
"""

from app.factory import create_app

app = create_app()
