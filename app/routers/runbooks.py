import html
import re
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, aliased
from starlette import status

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import RunbookImage, RunbookPage, RunbookPageHistory, RunbookSpace
from app.routers.auth import require_editor, require_user
from app.services.audit import write_audit

router = APIRouter(prefix="/documentation/runbook-manager")
templates = Jinja2Templates(directory="app/templates")
RUNBOOK_IMAGE_TYPES = {
    ".gif": ("image/gif", (b"GIF87a", b"GIF89a")),
    ".jpg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".jpeg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".png": ("image/png", (b"\x89PNG\r\n\x1a\n",)),
    ".webp": ("image/webp", (b"RIFF",)),
}
RUNBOOK_TEMPLATES = {
    "incident-response": ("Incident response", "# Incident overview\n\n## Impact\n\n## Immediate actions\n\n- [ ] Confirm the incident\n- [ ] Notify responders\n\n## Recovery\n\n## Follow-up"),
    "service-recovery": ("Service recovery", "# Service recovery\n\n## Symptoms\n\n## Prerequisites\n\n## Recovery steps\n\n1. Verify service health\n2. Restore service\n3. Validate recovery\n\n## Rollback"),
    "new-service-build": ("New service build", "# New service build\n\n## Purpose\n\n## Dependencies\n\n## Build steps\n\n## Validation\n\n## Ownership"),
    "backup-restoration": ("Backup restoration", "# Backup restoration\n\n## Backup source\n\n## Restore procedure\n\n## Integrity checks\n\n## Recovery record"),
    "routine-maintenance": ("Routine maintenance", "# Routine maintenance\n\n## Schedule\n\n## Preparation\n\n- [ ] Confirm maintenance window\n- [ ] Confirm backup\n\n## Procedure\n\n## Validation"),
    "troubleshooting-guide": ("Troubleshooting guide", "# Troubleshooting guide\n\n## Symptoms\n\n## Checks\n\n## Resolution\n\n## Escalation"),
    "change-procedure": ("Change procedure", "# Change procedure\n\n## Objective\n\n## Risk\n\n## Implementation\n\n## Validation\n\n## Rollback"),
    "disaster-recovery-test": ("Disaster recovery test", "# Disaster recovery test\n\n## Scope\n\n## Success criteria\n\n## Test steps\n\n## Results\n\n## Actions"),
}


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "runbook-page"


def unique_slug(db: Session, title: str, page_id: int | None = None) -> str:
    base = slugify(title)
    slug = base
    counter = 2
    while True:
        query = db.query(RunbookPage).filter(RunbookPage.slug == slug)
        if page_id:
            query = query.filter(RunbookPage.id != page_id)
        if not query.first():
            return slug
        slug = f"{base}-{counter}"
        counter += 1


def tag_list(tags: str | None) -> list[str]:
    if not tags:
        return []
    return [part.strip() for part in tags.split(",") if part.strip()]


def clean_tags(tags: str) -> str | None:
    parts = []
    seen = set()
    for tag in tag_list(tags):
        key = tag.lower()
        if key not in seen:
            parts.append(tag[:40])
            seen.add(key)
    return ", ".join(parts) or None


def validate_runbook_image(filename: str, data: bytes) -> tuple[str, str]:
    clean_filename = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    suffix = f".{clean_filename.rsplit('.', 1)[-1].lower()}" if "." in clean_filename else ".png"
    allowed = RUNBOOK_IMAGE_TYPES.get(suffix)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Image must be a PNG, JPEG, GIF, or WebP file.")
    content_type, signatures = allowed
    if suffix == ".webp":
        if len(data) < 12 or not data.startswith(b"RIFF") or data[8:12] != b"WEBP":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Image content does not match its file type.")
    elif not any(data.startswith(signature) for signature in signatures):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Image content does not match its file type.")
    return suffix, content_type


def filename_stem(filename: str | None, fallback: str = "Pasted image") -> str:
    clean_filename = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    stem = clean_filename.rsplit(".", 1)[0] if "." in clean_filename else clean_filename
    return stem or fallback


def markdown_to_html(markdown: str | None) -> str:
    if not markdown:
        return '<p class="muted">No content yet.</p>'

    lines = markdown.replace("\r\n", "\n").split("\n")
    output: list[str] = []
    paragraph: list[str] = []
    list_type: str | None = None
    in_code = False
    code_language = ""
    code_lines: list[str] = []

    def clean_code_language(value: str) -> str:
        return re.sub(r"[^a-z0-9_+#.-]", "", value.strip().lower())[:40]

    def inline(text: str) -> str:
        escaped = html.escape(text)
        images: list[str] = []
        links: list[str] = []

        def replace_image(match: re.Match) -> str:
            alt = html.escape(match.group(1), quote=True)
            src = match.group(2)
            images.append(f'<img src="{src}" alt="{alt}" loading="lazy">')
            return f"@@RUNBOOKIMAGE{len(images) - 1}@@"

        def replace_link(match: re.Match) -> str:
            label = match.group(1)
            href = match.group(2)
            external = href.startswith("http")
            attributes = ' target="_blank" rel="noopener noreferrer"' if external else ""
            links.append(f'<a href="{href}"{attributes}>{label}</a>')
            return f"@@RUNBOOKLINK{len(links) - 1}@@"

        escaped = re.sub(
            r"!\[([^\]]*)\]\((https?://[^\s)]+|/[^\s)]+)\)",
            replace_image,
            escaped,
        )
        escaped = re.sub(
            r"\[([^\]]+)\]\((https?://[^\s)]+|/[^\s)]+|#[^\s)]+)\)",
            replace_link,
            escaped,
        )
        escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
        escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
        escaped = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", escaped)
        escaped = re.sub(
            r"(https?://[^\s<]+)",
            r'<a href="\1" target="_blank" rel="noopener noreferrer">\1</a>',
            escaped,
        )
        for index, image in enumerate(images):
            escaped = escaped.replace(f"@@RUNBOOKIMAGE{index}@@", image)
        for index, link in enumerate(links):
            escaped = escaped.replace(f"@@RUNBOOKLINK{index}@@", link)
        return escaped

    def render_code_block() -> str:
        language = clean_code_language(code_language)
        label = html.escape(language or "auto")
        language_class = f' class="language-{html.escape(language)}"' if language else ""
        code = html.escape(chr(10).join(code_lines))
        return (
            f'<div class="runbook-code-block" data-code-language="{label}">'
            f'<div class="runbook-code-header"><span class="runbook-code-language-label">{label}</span>'
            '<button class="runbook-code-copy" type="button" data-runbook-copy-code aria-label="Copy code">Copy</button>'
            f'</div><pre><code{language_class}>{code}</code></pre></div>'
        )

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            output.append(f"<p>{'<br>'.join(inline(line) for line in paragraph)}</p>")
            paragraph = []

    def close_list() -> None:
        nonlocal list_type
        if list_type:
            output.append(f"</{list_type}>")
            list_type = None

    for line in lines:
        stripped = line.strip()
        fence = re.match(r"^```([A-Za-z0-9_+#.-]*)\s*$", stripped)

        if fence:
            if in_code:
                output.append(render_code_block())
                code_lines = []
                code_language = ""
                in_code = False
            else:
                flush_paragraph()
                close_list()
                in_code = True
                code_language = clean_code_language(fence.group(1))
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not stripped:
            flush_paragraph()
            close_list()
            continue

        heading = re.match(r"^(#{1,3})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            close_list()
            level = len(heading.group(1)) + 1
            output.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
            continue

        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            flush_paragraph()
            close_list()
            output.append("<hr>")
            continue

        quote = re.match(r"^>\s?(.+)$", stripped)
        if quote:
            flush_paragraph()
            close_list()
            output.append(f"<blockquote>{inline(quote.group(1))}</blockquote>")
            continue

        list_item = re.match(r"^([-*]|\d+\.)\s+(.+)$", stripped)
        if list_item:
            flush_paragraph()
            next_type = "ol" if list_item.group(1)[0].isdigit() else "ul"
            if list_type and list_type != next_type:
                close_list()
            if not list_type:
                start = int(list_item.group(1)[:-1]) if next_type == "ol" else 1
                output.append(f'<ol start="{start}">' if next_type == "ol" and start > 1 else f"<{next_type}>")
                list_type = next_type
            checkbox = re.match(r"^\[([ xX])\]\s+(.+)$", list_item.group(2))
            if checkbox:
                checked = " checked" if checkbox.group(1).lower() == "x" else ""
                output.append(f'<li class="runbook-task"><input type="checkbox" disabled{checked}> {inline(checkbox.group(2))}</li>')
            else:
                output.append(f"<li>{inline(list_item.group(2))}</li>")
            continue

        paragraph.append(stripped)

    if in_code:
        output.append(render_code_block())
    flush_paragraph()
    close_list()
    return "\n".join(output)
def spaces_for_select(db: Session) -> list[RunbookSpace]:
    return db.query(RunbookSpace).order_by(RunbookSpace.sort_order.asc(), RunbookSpace.name.asc()).all()


def pages_for_parent_select(db: Session, page_id: int | None = None, space_id: int | None = None) -> list[RunbookPage]:
    query = db.query(RunbookPage)
    if page_id:
        query = query.filter(RunbookPage.id != page_id)
    if space_id is not None:
        query = query.filter(RunbookPage.space_id == space_id)
    return query.order_by(RunbookPage.title.asc()).all()


def validate_page_relationships(db: Session, space_id: int | None, parent_id: int | None, page_id: int | None = None) -> None:
    if space_id is not None and not db.get(RunbookSpace, space_id):
        raise HTTPException(status_code=400, detail="Selected space does not exist.")
    if parent_id is None:
        return
    parent = db.get(RunbookPage, parent_id)
    if not parent or parent.id == page_id:
        raise HTTPException(status_code=400, detail="Selected parent page is not available.")
    if parent.space_id != space_id:
        raise HTTPException(status_code=400, detail="Parent page must be in the selected space.")
    ancestor = parent
    seen = set()
    while ancestor and ancestor.parent_id and ancestor.id not in seen:
        seen.add(ancestor.id)
        if ancestor.parent_id == page_id:
            raise HTTPException(status_code=400, detail="A page cannot be moved beneath one of its children.")
        ancestor = db.get(RunbookPage, ancestor.parent_id)


def all_tag_stats(pages: list[RunbookPage]) -> list[dict]:
    stats: dict[str, dict] = {}
    for page in pages:
        for tag in tag_list(page.tags):
            key = tag.casefold()
            row = stats.setdefault(key, {"name": tag, "count": 0, "last_used": page.updated_at})
            row["count"] += 1
            if page.updated_at and (not row["last_used"] or page.updated_at > row["last_used"]):
                row["last_used"] = page.updated_at
    return sorted(stats.values(), key=lambda item: (-item["count"], item["name"].casefold()))


def runbook_context(active: str) -> dict:
    return {"runbook_active": active, "tag_list": tag_list}


def hierarchical_pages(pages: list[RunbookPage]) -> list[dict]:
    page_map = {page.id: page for page in pages}
    order = {page.id: index for index, page in enumerate(pages)}
    children_by_parent: dict[int, list[RunbookPage]] = {}
    roots: list[RunbookPage] = []

    for page in pages:
        if page.parent_id and page.parent_id in page_map:
            children_by_parent.setdefault(page.parent_id, []).append(page)
        else:
            roots.append(page)

    def sort_key(page: RunbookPage) -> tuple:
        return (page.title.lower(), order.get(page.id, 0))

    for children in children_by_parent.values():
        children.sort(key=sort_key)

    flattened: list[dict] = []

    def add_page(page: RunbookPage, depth: int, seen: set[int]) -> None:
        if page.id in seen:
            return
        next_seen = {*seen, page.id}
        flattened.append({"page": page, "depth": depth})
        for child in children_by_parent.get(page.id, []):
            add_page(child, depth + 1, next_seen)

    for root in roots:
        add_page(root, 0, set())

    return flattened


def optional_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


@router.get("")
def runbook_home(
    request: Request,
    q: str = Query("", max_length=200),
    space: int | None = Query(None),
    tag: str = Query("", max_length=80),
    tab: str = Query("recent", pattern="^(recent|pinned|frequent)$"),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    spaces = spaces_for_select(db)
    parent_alias = aliased(RunbookPage)
    query = db.query(RunbookPage).outerjoin(RunbookSpace, RunbookPage.space_id == RunbookSpace.id).outerjoin(parent_alias, RunbookPage.parent_id == parent_alias.id)
    clean_q = q.strip()
    clean_tag = tag.strip()

    if space:
        query = query.filter(RunbookPage.space_id == space)
    if clean_tag:
        query = query.filter(RunbookPage.tags.ilike(f"%{clean_tag}%"))
    if clean_q:
        like = f"%{clean_q}%"
        query = query.filter(
            or_(
                RunbookPage.title.ilike(like),
                RunbookPage.summary.ilike(like),
                RunbookPage.body.ilike(like),
                RunbookPage.tags.ilike(like),
                RunbookSpace.name.ilike(like),
                parent_alias.title.ilike(like),
            )
        )
    if tab == "pinned":
        query = query.filter(RunbookPage.is_pinned.is_(True))
        order = (RunbookPage.updated_at.desc(), RunbookPage.title.asc())
    elif tab == "frequent":
        order = (RunbookPage.view_count.desc(), RunbookPage.updated_at.desc())
    else:
        order = (RunbookPage.updated_at.desc(), RunbookPage.title.asc())
    pages = query.order_by(*order).limit(100).all()
    all_pages = db.query(RunbookPage).all()
    tag_stats = all_tag_stats(all_pages)
    now = datetime.utcnow()
    most_used = max(all_pages, key=lambda page: (page.view_count or 0, page.updated_at or datetime.min), default=None)
    needs_review = [page for page in all_pages if not page.summary or not page.space_id or not page.tags or (page.updated_at and page.updated_at < now - timedelta(days=180))]

    return templates.TemplateResponse(
        request,
        "runbooks.html",
        {
            "user": user,
            "pages": pages,
            "table_pages": hierarchical_pages(pages),
            "spaces": spaces,
            "total": db.query(RunbookPage).count(),
            "updated_recently": sum(1 for page in all_pages if page.updated_at and page.updated_at >= now - timedelta(days=7)),
            "pinned_total": sum(1 for page in all_pages if page.is_pinned),
            "most_used": most_used,
            "tab": tab,
            "tag_stats": tag_stats[:8],
            "needs_review": needs_review[:5],
            "q": clean_q,
            "active_space": space,
            "active_tag": clean_tag,
            **runbook_context("overview" if not clean_q and not space and not clean_tag else "runbooks"),
            **csrf_context(request),
        },
    )


@router.get("/runbooks")
def runbooks_page(
    request: Request,
    q: str = Query("", max_length=200),
    space: int | None = Query(None),
    tag: str = Query("", max_length=80),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    spaces = spaces_for_select(db)
    parent_alias = aliased(RunbookPage)
    query = db.query(RunbookPage).outerjoin(RunbookSpace, RunbookPage.space_id == RunbookSpace.id).outerjoin(parent_alias, RunbookPage.parent_id == parent_alias.id)
    clean_q = q.strip()
    clean_tag = tag.strip()
    if space:
        query = query.filter(RunbookPage.space_id == space)
    if clean_tag:
        query = query.filter(RunbookPage.tags.ilike(f"%{clean_tag}%"))
    if clean_q:
        like = f"%{clean_q}%"
        query = query.filter(or_(RunbookPage.title.ilike(like), RunbookPage.summary.ilike(like), RunbookPage.body.ilike(like), RunbookPage.tags.ilike(like), RunbookSpace.name.ilike(like), parent_alias.title.ilike(like)))
    pages = query.order_by(RunbookPage.is_pinned.desc(), RunbookPage.updated_at.desc(), RunbookPage.title.asc()).limit(500).all()
    return templates.TemplateResponse(
        request,
        "runbook_index.html",
        {
            "user": user,
            "pages": pages,
            "table_pages": hierarchical_pages(pages),
            "spaces": spaces,
            "tag_stats": all_tag_stats(db.query(RunbookPage).all()),
            "q": clean_q,
            "active_space": space,
            "active_tag": clean_tag,
            **runbook_context("runbooks"),
            **csrf_context(request),
        },
    )


@router.get("/spaces")
def spaces_page(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    spaces = spaces_for_select(db)
    counts = dict(db.query(RunbookPage.space_id, func.count(RunbookPage.id)).group_by(RunbookPage.space_id).all())
    children = dict(db.query(RunbookPage.space_id, func.count(RunbookPage.id)).filter(RunbookPage.parent_id.is_not(None)).group_by(RunbookPage.space_id).all())
    latest = dict(db.query(RunbookPage.space_id, func.max(RunbookPage.updated_at)).group_by(RunbookPage.space_id).all())
    rows = [{"space": item, "count": counts.get(item.id, 0), "children": children.get(item.id, 0), "updated_at": latest.get(item.id)} for item in spaces]
    return templates.TemplateResponse(request, "runbook_spaces.html", {"user": user, "space_rows": rows, **runbook_context("spaces"), **csrf_context(request)})


@router.get("/tags")
def tags_page(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    return templates.TemplateResponse(request, "runbook_tags.html", {"user": user, "tag_stats": all_tag_stats(db.query(RunbookPage).all()), **runbook_context("tags"), **csrf_context(request)})


@router.post("/tags/rename")
def rename_tag(request: Request, old_name: str = Form(..., max_length=80), new_name: str = Form("", max_length=80), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    old_key = old_name.strip().casefold()
    replacement = new_name.strip()[:40]
    changed = 0
    for page in db.query(RunbookPage).all():
        current = tag_list(page.tags)
        if not any(tag.casefold() == old_key for tag in current):
            continue
        page.tags = clean_tags(", ".join([replacement if tag.casefold() == old_key else tag for tag in current]))
        page.updated_at = datetime.utcnow()
        changed += 1
    db.commit()
    write_audit(db, user, "update", "runbook_tag", old_name, request.client.host if request.client else None, detail=f"{old_name} -> {replacement or 'deleted'} ({changed} pages)")
    return RedirectResponse("/documentation/runbook-manager/tags", status_code=303)


@router.get("/templates")
def templates_page(request: Request, user=Depends(require_user)):
    items = [{"key": key, "name": value[0], "body": value[1]} for key, value in RUNBOOK_TEMPLATES.items()]
    return templates.TemplateResponse(request, "runbook_templates.html", {"user": user, "runbook_templates": items, **runbook_context("templates"), **csrf_context(request)})


@router.get("/import")
def import_page(request: Request, db: Session = Depends(get_db), user=Depends(require_editor)):
    spaces = spaces_for_select(db)
    return templates.TemplateResponse(request, "runbook_import.html", {"user": user, "spaces": spaces, **runbook_context("import"), **csrf_context(request)})


@router.post("/import")
async def import_page_file(request: Request, document: UploadFile = File(...), space_id: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    filename = (document.filename or "Imported runbook.md").replace("\\", "/").rsplit("/", 1)[-1]
    if not filename.lower().endswith((".md", ".markdown", ".txt")):
        raise HTTPException(status_code=400, detail="Import a Markdown or plain-text file.")
    data = await document.read(200001)
    if len(data) > 200000:
        raise HTTPException(status_code=413, detail="Runbook files must be 200 KB or smaller.")
    try:
        body = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Runbook files must use UTF-8 encoding.") from exc
    title = filename.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").strip()[:255] or "Imported runbook"
    selected_space = optional_int(space_id)
    validate_page_relationships(db, selected_space, None)
    row = RunbookPage(title=title, slug=unique_slug(db, title), body=body.strip() or None, space_id=selected_space, created_by_id=user.id, updated_by_id=user.id)
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "runbook_page", str(row.id), request.client.host if request.client else None, detail=f"Imported {filename}")
    return RedirectResponse(f"/documentation/runbook-manager/{row.slug}/edit", status_code=303)


@router.post("/spaces")
def create_space(
    request: Request,
    name: str = Form(..., max_length=160),
    description: str = Form("", max_length=1000),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Space name is required.")
    if db.query(RunbookSpace).filter(RunbookSpace.name == clean_name).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="That space already exists.")
    row = RunbookSpace(name=clean_name, description=description.strip() or None)
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "runbook_space", str(row.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse("/documentation/runbook-manager/spaces", status_code=303)


@router.post("/spaces/{space_id}/delete")
def delete_space(request: Request, space_id: int, handling: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(RunbookSpace, space_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runbook space not found")
    page_count = db.query(RunbookPage).filter(RunbookPage.space_id == row.id).count()
    if page_count and handling != "unassign":
        raise HTTPException(status_code=400, detail="Choose to leave the existing runbooks unassigned before deleting this non-empty space.")
    name = row.name
    db.query(RunbookPage).filter(RunbookPage.space_id == row.id).update(
        {RunbookPage.space_id: None}, synchronize_session=False
    )
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "runbook_space", str(space_id), request.client.host if request.client else None, detail=name)
    return RedirectResponse("/documentation/runbook-manager/spaces", status_code=303)


@router.post("/images")
async def upload_runbook_image(
    request: Request,
    csrf_token: str = Form(...),
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    data = await image.read(get_settings().max_upload_mb * 1024 * 1024 + 1)
    if len(data) > get_settings().max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Image is larger than {get_settings().max_upload_mb} MB.")
    _suffix, content_type = validate_runbook_image(image.filename or "pasted-image.png", data)
    row = RunbookImage(
        original_filename=image.filename or None,
        content_type=content_type,
        size_bytes=len(data),
        data=data,
        uploaded_by_id=user.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    alt = filename_stem(image.filename).replace("-", " ").replace("_", " ").strip() or "Pasted image"
    alt = re.sub(r"[\[\]()]+", "", alt)[:120] or "Pasted image"
    url = f"/documentation/runbook-manager/images/{row.id}"
    return JSONResponse({"url": url, "markdown": f"![{alt}]({url})", "content_type": content_type})


@router.get("/images/{image_id}")
def runbook_image(image_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    image = db.get(RunbookImage, image_id)
    if not image or not image.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
    return Response(content=image.data, media_type=image.content_type)


@router.get("/new")
def new_page(request: Request, template: str = Query("", max_length=80), space: int | None = Query(None), db: Session = Depends(get_db), user=Depends(require_editor)):
    template_data = RUNBOOK_TEMPLATES.get(template)
    return templates.TemplateResponse(
        request,
        "runbook_form.html",
        {
            "user": user,
            "page": None,
            "spaces": spaces_for_select(db),
            "parents": pages_for_parent_select(db, space_id=space) if space is not None else pages_for_parent_select(db),
            "initial_space_id": space,
            "initial_title": template_data[0] if template_data else "",
            "initial_body": template_data[1] if template_data else "",
            "existing_tags": [item["name"] for item in all_tag_stats(db.query(RunbookPage).all())],
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/new")
def create_page(
    request: Request,
    title: str = Form(..., max_length=255),
    summary: str = Form("", max_length=500),
    body: str = Form("", max_length=200000),
    tags: str = Form("", max_length=500),
    space_id: str = Form(""),
    parent_id: str = Form(""),
    is_pinned: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    clean_title = title.strip()
    if not clean_title:
        return templates.TemplateResponse(
            request,
            "runbook_form.html",
            {"user": user, "page": None, "spaces": spaces_for_select(db), "parents": pages_for_parent_select(db), "error": "Title is required.", **csrf_context(request)},
            status_code=400,
        )
    selected_space = optional_int(space_id)
    selected_parent = optional_int(parent_id)
    validate_page_relationships(db, selected_space, selected_parent)
    row = RunbookPage(
        title=clean_title,
        slug=unique_slug(db, clean_title),
        summary=summary.strip() or None,
        body=body.strip() or None,
        tags=clean_tags(tags),
        space_id=selected_space,
        parent_id=selected_parent,
        is_pinned=bool(is_pinned),
        created_by_id=user.id,
        updated_by_id=user.id,
    )
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "runbook_page", str(row.id), request.client.host if request.client else None, detail=row.title)
    return RedirectResponse(f"/documentation/runbook-manager/{row.slug}", status_code=303)


@router.get("/{slug}")
def view_page(slug: str, request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    page = db.query(RunbookPage).filter(RunbookPage.slug == slug).first()
    if not page:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runbook page not found")
    page.view_count = (page.view_count or 0) + 1
    page.last_viewed_at = datetime.utcnow()
    db.commit()
    children = db.query(RunbookPage).filter(RunbookPage.parent_id == page.id).order_by(RunbookPage.title.asc()).all()
    history = db.query(RunbookPageHistory).filter(RunbookPageHistory.page_id == page.id).order_by(RunbookPageHistory.saved_at.desc()).limit(10).all()
    return templates.TemplateResponse(
        request,
        "runbook_detail.html",
        {
            "user": user,
            "page": page,
            "children": children,
            "history": history,
            "body_html": markdown_to_html(page.body),
            "tag_list": tag_list,
            **csrf_context(request),
        },
    )


@router.get("/{slug}/edit")
def edit_page(slug: str, request: Request, db: Session = Depends(get_db), user=Depends(require_editor)):
    page = db.query(RunbookPage).filter(RunbookPage.slug == slug).first()
    if not page:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runbook page not found")
    return templates.TemplateResponse(
        request,
        "runbook_form.html",
        {
            "user": user,
            "page": page,
            "spaces": spaces_for_select(db),
            "parents": pages_for_parent_select(db, page.id),
            "initial_space_id": page.space_id,
            "initial_title": "",
            "initial_body": "",
            "existing_tags": [item["name"] for item in all_tag_stats(db.query(RunbookPage).all())],
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/{slug}/edit")
def update_page(
    slug: str,
    request: Request,
    title: str = Form(..., max_length=255),
    summary: str = Form("", max_length=500),
    body: str = Form("", max_length=200000),
    tags: str = Form("", max_length=500),
    space_id: str = Form(""),
    parent_id: str = Form(""),
    is_pinned: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    page = db.query(RunbookPage).filter(RunbookPage.slug == slug).first()
    if not page:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runbook page not found")
    clean_title = title.strip()
    if not clean_title:
        return templates.TemplateResponse(
            request,
            "runbook_form.html",
            {"user": user, "page": page, "spaces": spaces_for_select(db), "parents": pages_for_parent_select(db, page.id), "error": "Title is required.", **csrf_context(request)},
            status_code=400,
        )

    db.add(
        RunbookPageHistory(
            page_id=page.id,
            title=page.title,
            summary=page.summary,
            body=page.body,
            tags=page.tags,
            saved_by_id=user.id,
        )
    )
    selected_space = optional_int(space_id)
    selected_parent = optional_int(parent_id)
    validate_page_relationships(db, selected_space, selected_parent, page.id)
    page.title = clean_title
    page.slug = unique_slug(db, clean_title, page.id)
    page.summary = summary.strip() or None
    page.body = body.strip() or None
    page.tags = clean_tags(tags)
    page.space_id = selected_space
    page.parent_id = selected_parent
    page.is_pinned = bool(is_pinned)
    page.updated_by_id = user.id
    page.updated_at = datetime.utcnow()
    db.commit()
    write_audit(db, user, "update", "runbook_page", str(page.id), request.client.host if request.client else None, detail=page.title)
    return RedirectResponse(f"/documentation/runbook-manager/{page.slug}", status_code=303)


@router.post("/{slug}/delete")
def delete_page(
    slug: str,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    page = db.query(RunbookPage).filter(RunbookPage.slug == slug).first()
    if not page:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runbook page not found")
    title = page.title
    db.query(RunbookPage).filter(RunbookPage.parent_id == page.id).update({"parent_id": None})
    db.query(RunbookPageHistory).filter(RunbookPageHistory.page_id == page.id).delete()
    db.delete(page)
    db.commit()
    write_audit(db, user, "delete", "runbook_page", None, request.client.host if request.client else None, detail=title)
    return RedirectResponse("/documentation/runbook-manager", status_code=303)
