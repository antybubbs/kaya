import html
import re
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette import status

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import RunbookPage, RunbookPageHistory, RunbookSpace
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


def runbook_image_dir() -> Path:
    path = Path(get_settings().upload_dir) / "runbook_images"
    path.mkdir(parents=True, exist_ok=True)
    return path


def validate_runbook_image(filename: str, data: bytes) -> tuple[str, str]:
    suffix = Path(filename or "").suffix.lower() or ".png"
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


def pages_for_parent_select(db: Session, page_id: int | None = None) -> list[RunbookPage]:
    query = db.query(RunbookPage)
    if page_id:
        query = query.filter(RunbookPage.id != page_id)
    return query.order_by(RunbookPage.title.asc()).all()


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
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    spaces = spaces_for_select(db)
    query = db.query(RunbookPage)
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
            )
        )

    pages = (
        query.order_by(RunbookPage.is_pinned.desc(), RunbookPage.updated_at.desc(), RunbookPage.title.asc())
        .limit(500)
        .all()
    )
    all_pages = db.query(RunbookPage).all()
    tags = sorted({tag for page in all_pages for tag in tag_list(page.tags)}, key=str.lower)

    return templates.TemplateResponse(
        request,
        "runbooks.html",
        {
            "user": user,
            "pages": pages,
            "table_pages": hierarchical_pages(pages),
            "spaces": spaces,
            "total": db.query(RunbookPage).count(),
            "q": clean_q,
            "active_space": space,
            "active_tag": clean_tag,
            "tags": tags,
            **csrf_context(request),
        },
    )


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
    return RedirectResponse(f"/documentation/runbook-manager?space={row.id}", status_code=303)


@router.post("/images")
async def upload_runbook_image(
    request: Request,
    csrf_token: str = Form(...),
    image: UploadFile = File(...),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    data = await image.read(get_settings().max_upload_mb * 1024 * 1024 + 1)
    if len(data) > get_settings().max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Image is larger than {get_settings().max_upload_mb} MB.")
    suffix, content_type = validate_runbook_image(image.filename or "pasted-image.png", data)
    stored = f"runbook-{uuid4().hex}{suffix}"
    path = runbook_image_dir() / stored
    path.write_bytes(data)
    alt = Path(image.filename or "Pasted image").stem.replace("-", " ").replace("_", " ").strip() or "Pasted image"
    alt = re.sub(r"[\[\]()]+", "", alt)[:120] or "Pasted image"
    url = f"/documentation/runbook-manager/images/{stored}"
    return JSONResponse({"url": url, "markdown": f"![{alt}]({url})", "content_type": content_type})


@router.get("/images/{filename}")
def runbook_image(filename: str, user=Depends(require_user)):
    if not re.fullmatch(r"runbook-[a-f0-9]{32}\.(png|jpg|jpeg|gif|webp)", filename):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
    path = runbook_image_dir() / filename
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
    suffix, content_type = validate_runbook_image(filename, path.read_bytes())
    return FileResponse(path, media_type=content_type)


@router.get("/new")
def new_page(request: Request, db: Session = Depends(get_db), user=Depends(require_editor)):
    return templates.TemplateResponse(
        request,
        "runbook_form.html",
        {
            "user": user,
            "page": None,
            "spaces": spaces_for_select(db),
            "parents": pages_for_parent_select(db),
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
    row = RunbookPage(
        title=clean_title,
        slug=unique_slug(db, clean_title),
        summary=summary.strip() or None,
        body=body.strip() or None,
        tags=clean_tags(tags),
        space_id=optional_int(space_id),
        parent_id=optional_int(parent_id),
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
    page.title = clean_title
    page.slug = unique_slug(db, clean_title, page.id)
    page.summary = summary.strip() or None
    page.body = body.strip() or None
    page.tags = clean_tags(tags)
    page.space_id = optional_int(space_id)
    page.parent_id = optional_int(parent_id)
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
