from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..database import SessionLocal
from ..models import Actor, Identifier
from ..services.actor_service import build_actor_dossier

router = APIRouter(
    prefix="/api/actors",
    tags=["actors"],
)


def _resolve_actor(actor_id: str, db: Session):
    clean_id = actor_id.strip()
    if not clean_id:
        return None

    actor = db.query(Actor).filter(Actor.actor_id == clean_id).first()
    if actor:
        return actor

    ident = (
        db.query(Identifier)
        .filter(Identifier.identifier_value.ilike(clean_id))
        .first()
    )
    if ident and ident.actor:
        return ident.actor

    return None


@router.get("/_debug/dbinfo")
def db_info():
    db = SessionLocal()
    try:
        row = db.execute(text(
            "SELECT current_database(), inet_server_addr()::text, "
            "(SELECT COUNT(*) FROM actors)"
        )).fetchone()
        return {
            "database": row[0],
            "host": row[1],
            "actor_count": row[2],
        }
    finally:
        db.close()


@router.get("/{actor_id}")
def get_actor(actor_id: str):
    db = SessionLocal()
    try:
        actor = _resolve_actor(actor_id, db)

        if not actor:
            raise HTTPException(
                status_code=404,
                detail=f"Actor '{actor_id}' not found.",
            )

        actor_detail = build_actor_dossier(actor, db, include_graph=True)

        return {"actor": actor_detail}

    finally:
        db.close()