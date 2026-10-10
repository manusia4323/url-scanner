"""FastAPI application factory and configuration."""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.config import settings
from app.database import init_db
from app.utils.http_client import get_async_client, close_async_client
from app.routers import scan, blacklist, logs

# Configure logging
logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    """
    # Startup
    logger.info("Starting URL Security Scanner API")
    try:
        init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        sys.exit(1)

    try:
        await get_async_client()
        logger.info("HTTP client initialized")
    except Exception as e:
        logger.error(f"Failed to initialize HTTP client: {e}")

    yield

    # Shutdown
    logger.info("Shutting down URL Security Scanner API")
    try:
        await close_async_client()
        logger.info("HTTP client closed")
    except Exception as e:
        logger.error(f"Error closing HTTP client: {e}")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="URL Security Scanner API",
        description="REST API for scanning URLs for security threats",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle validation errors with structured response."""
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Validation error: {exc.errors()[0]['msg']}",
                "code": "VALIDATION_ERROR"
            }
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions."""
        logger.error(f"Unexpected error: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "code": "INTERNAL_ERROR"
            }
        )

    # Include routers
    app.include_router(scan.router)
    app.include_router(blacklist.router)
    app.include_router(logs.router)

    # Health check endpoint
    @app.get("/health", tags=["health"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "ok", "version": "1.0.0"}

    # Root endpoint
    @app.get("/", tags=["root"])
    async def root():
        """Root endpoint with API information."""
        return {
            "name": "URL Security Scanner API",
            "version": "1.0.0",
            "docs": "/docs",
            "openapi": "/openapi.json"
        }

    logger.info("FastAPI application created")
    return app


# Create application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level=settings.log_level,
    )