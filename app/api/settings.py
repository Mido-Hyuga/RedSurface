"""
Settings API — Manage API keys and module configuration.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import ModuleConfig, get_db

router = APIRouter(tags=["settings"])


class ApiKeyUpdate(BaseModel):
    """Request body for updating a module's API key."""
    api_key: str


class ModuleToggle(BaseModel):
    """Enable/disable a module."""
    enabled: bool


@router.get("/settings/modules")
def list_module_configs(db: Session = Depends(get_db)):
    """List all module configurations (API keys and enabled status)."""
    configs = db.query(ModuleConfig).all()
    return [c.to_dict() for c in configs]


@router.put("/settings/modules/{module_name}/key")
def set_api_key(module_name: str, body: ApiKeyUpdate, db: Session = Depends(get_db)):
    """Set or update an API key for a module."""
    config = db.query(ModuleConfig).filter(
        ModuleConfig.module_name == module_name
    ).first()

    if not config:
        config = ModuleConfig(module_name=module_name, api_key=body.api_key)
        db.add(config)
    else:
        config.api_key = body.api_key

    db.commit()
    return config.to_dict()


@router.put("/settings/modules/{module_name}/toggle")
def toggle_module(module_name: str, body: ModuleToggle, db: Session = Depends(get_db)):
    """Enable or disable a module."""
    config = db.query(ModuleConfig).filter(
        ModuleConfig.module_name == module_name
    ).first()

    if not config:
        config = ModuleConfig(module_name=module_name, enabled=body.enabled)
        db.add(config)
    else:
        config.enabled = body.enabled

    db.commit()
    return config.to_dict()


@router.delete("/settings/modules/{module_name}/key")
def delete_api_key(module_name: str, db: Session = Depends(get_db)):
    """Remove an API key for a module."""
    config = db.query(ModuleConfig).filter(
        ModuleConfig.module_name == module_name
    ).first()
    if not config:
        raise HTTPException(status_code=404, detail="Module config not found")

    config.api_key = None
    db.commit()
    return {"detail": "API key removed"}
