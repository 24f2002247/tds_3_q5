import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .config import get_settings
from .database import init_db
from .decision_engine import DecisionEngine
from .schemas import CommitRequest, ProposeRequest
from .service import ConflictError, MailroomService, NotFoundError

_REF_TEMPLATE = "#/components/schemas/{model}"


def _build_openapi_schema(application: FastAPI) -> dict[str, Any]:
    openapi_schema = get_openapi(
        title=application.title,
        version=application.version,
        description=application.description,
        routes=application.routes,
    )

    propose_schema = ProposeRequest.model_json_schema(ref_template=_REF_TEMPLATE)
    commit_schema = CommitRequest.model_json_schema(ref_template=_REF_TEMPLATE)

    components = openapi_schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas.update(propose_schema.pop("$defs", {}))
    schemas.update(commit_schema.pop("$defs", {}))

    schemas["ProposeRequest"] = propose_schema
    schemas["CommitRequest"] = commit_schema

    request_body_spec = {
        "required": True,
        "content": {
            "application/json": {
                "schema": {
                    "oneOf": [
                        {"$ref": "#/components/schemas/ProposeRequest"},
                        {"$ref": "#/components/schemas/CommitRequest"},
                    ],
                    "discriminator": {"propertyName": "operation"},
                }
            }
        },
    }

    paths = openapi_schema.get("paths", {})
    for path_str in ["/v1/mailroom/actions", "/mailroom", "/"]:
        post_op = paths.get(path_str, {}).get("post")
        if post_op is not None:
            post_op["requestBody"] = request_body_spec

    return openapi_schema


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Safe AI Mailroom Action Gate",
    version="2.0.0",
    description="Audits mail dossiers, proposes safe actions, verifies scoped authority, and executes signed receipts under ga5-mailroom-action-gate/v2.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

settings = get_settings()
service = MailroomService(DecisionEngine(settings.ai_provider))

_openapi_cache: dict[str, Any] | None = None


def _openapi() -> dict[str, Any]:
    global _openapi_cache
    if _openapi_cache is None:
        _openapi_cache = _build_openapi_schema(app)
    return _openapi_cache


app.openapi = _openapi  # type: ignore[method-assign]


@app.get("/health")
@app.get("/healthz")
@app.get("/")
def health():
    return {
        "status": "ok",
        "service": "Safe AI Mailroom Action Gate",
        "profile": "ga5-mailroom-action-gate/v2",
    }


async def handle_action_request(request: Request) -> JSONResponse:
    try:
        body = await request.body()
        if len(body) > settings.max_body_bytes:
            return JSONResponse({"error": "request payload too large"}, status_code=413)

        raw = json.loads(body)
        if not isinstance(raw, dict):
            return JSONResponse({"error": "request body must be a JSON object"}, status_code=400)

        operation = raw.get("operation")
        if not operation:
            if request.url.path.endswith("commit"):
                operation = "commit"
            elif request.url.path.endswith("propose"):
                operation = "propose"

        if raw.get("profile") != "ga5-mailroom-action-gate/v2":
            return JSONResponse({"error": "unsupported profile; expected ga5-mailroom-action-gate/v2"}, status_code=400)

        if operation == "propose":
            parsed = ProposeRequest.model_validate(raw)
            result = service.propose(parsed)
        elif operation == "commit":
            parsed = CommitRequest.model_validate(raw)
            result = service.commit(parsed)
        else:
            return JSONResponse({"error": "invalid operation; must be 'propose' or 'commit'"}, status_code=400)

        encoded = json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > 512 * 1024:
            return JSONResponse({"error": "response size exceeds 512 KiB limit"}, status_code=413)

        return JSONResponse(content=result, media_type="application/json")

    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)
    except ConflictError as exc:
        return JSONResponse({"error": str(exc)}, status_code=409)
    except NotFoundError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)


# Register endpoints across all common paths
@app.post("/")
@app.post("/mailroom")
@app.post("/mailroom/")
@app.post("/mailroom/actions")
@app.post("/v1/mailroom/actions")
@app.post("/propose")
@app.post("/commit")
async def actions(request: Request):
    return await handle_action_request(request)
