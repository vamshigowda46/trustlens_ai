"""
TrustLens AI – producer.py
Enqueues background tasks to AWS SQS.
Falls back silently if SQS is not configured.
"""
import os, json, logging
import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

QUEUE_URL = os.environ.get('SQS_QUEUE_URL', '')
REGION    = os.environ.get('AWS_REGION', 'ap-south-1')

def _client():
    return boto3.client(
        'sqs',
        region_name=REGION,
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
    )

def enqueue(task_type: str, payload: dict, dedup_id: str = None) -> bool:
    """
    Send a task message to SQS.
    task_type: 'qr_scan' | 'app_analysis' | 'whatsapp_bot' | 'email_alert'
    Returns True on success, False on failure (non-blocking).
    """
    if not QUEUE_URL:
        logger.debug("SQS not configured – skipping enqueue for %s", task_type)
        return False
    try:
        msg = json.dumps({"task_type": task_type, "payload": payload})
        kwargs = {
            "QueueUrl": QUEUE_URL,
            "MessageBody": msg,
            "MessageAttributes": {
                "TaskType": {"StringValue": task_type, "DataType": "String"}
            },
        }
        if dedup_id:
            kwargs["MessageDeduplicationId"] = dedup_id
            kwargs["MessageGroupId"] = task_type
        _client().send_message(**kwargs)
        logger.info("Enqueued %s task", task_type)
        return True
    except (BotoCoreError, ClientError) as e:
        logger.warning("SQS enqueue failed: %s", e)
        return False

def enqueue_qr_scan(user_id: int, image_path: str):
    return enqueue("qr_scan", {"user_id": user_id, "image_path": image_path})

def enqueue_app_analysis(user_id: int, app_name: str, permissions: str):
    return enqueue("app_analysis", {"user_id": user_id, "app_name": app_name, "permissions": permissions})

def enqueue_whatsapp(from_number: str, message: str, lang: str = "en"):
    return enqueue("whatsapp_bot", {"from": from_number, "message": message, "lang": lang})

def enqueue_email_alert(user_email: str, scan_type: str, result: str):
    return enqueue("email_alert", {"email": user_email, "scan_type": scan_type, "result": result})
