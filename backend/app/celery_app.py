"""
Celery Configuration for Async Job Processing
Handles repository scanning, file analysis, and result aggregation
"""
from celery import Celery
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery instance
celery_app = Celery(
    "ai_security_auditor",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "app.tasks.repository_tasks",
        "app.tasks.file_analysis_tasks"
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_disable_rate_limits=True,
    task_routes={
        "app.tasks.repository_tasks.*": {"queue": "repository_scanning"},
        "app.tasks.file_analysis_tasks.*": {"queue": "file_analysis"},
    },
    task_default_queue="default",
    task_default_exchange="default",
    task_default_exchange_type="direct",
    task_default_routing_key="default",
)

# Task result configuration
celery_app.conf.result_expires = 3600  # 1 hour

if __name__ == "__main__":
    celery_app.start()
