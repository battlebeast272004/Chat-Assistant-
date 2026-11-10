from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness check. Kept dependency-free so it stays fast and never fails
    because of the database; DB readiness is verified at startup."""
    return {"status": "healthy"}
