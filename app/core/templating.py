"""Shared Jinja environment with a working-directory-independent loader."""

from fastapi.templating import Jinja2Templates

from app.core.paths import TEMPLATE_DIR


templates = Jinja2Templates(directory=TEMPLATE_DIR)

