"""Auth module ORM models.

The Foundation delegates credential material to a managed identity provider, so
no credentials are stored here. Session state lives in Redis, not Postgres
(see app.auth.service.SessionService). Models are defined in later tasks
(task 2.2); this module exists to anchor the package layout.
"""

from __future__ import annotations

# ORM models (if any) are added in task 2.2. The User entity itself lives in
# the Users module (app.users.models).
