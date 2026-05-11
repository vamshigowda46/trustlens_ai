"""
TrustLens AI – consumer.py
Polls AWS SQS and processes background tasks.
Run separately: python consumer.py
Supports retry (maxReceiveCount via SQS redrive policy) + DLQ.
"""
import os, json, time, logging
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

QUEUE_URL = os.environ.get('SQS_QUEUE_URL', '')
REGION    = os.environ.get('AWS_REGION', 'ap-south-1')
POLL_WAIT = 20  # long-polling seconds



# ── Task Handlers ──────────────────────────────────────────────────────────────
def handle_qr_scan(payload: dict):
    logger.info("Processing QR scan for user %s", payload.get('user_id'))
    # TODO: call ai_engine.scan_qr_image(payload['image_path'])

def handle_app_analysis(payload: dict):
    logger.info("Processing app analysis: %s", payload.get('app_name'))
    # TODO: call ai_engine.detect_loan_app(...)

def handle_whatsapp_bot(payload: dict):
    logger.info("Processing WhatsApp message from %s", payload.get('from'))
    # TODO: call Twilio API + AWS Translate + ai_engine response

def handle_email_alert(payload: dict):
    logger.info("Sending email alert to %s", payload.get('email'))
    # TODO: send via SES or SMTP

HANDLERS = {
    "qr_scan":       handle_qr_scan,
    "app_analysis":  handle_app_analysis,
    "whatsapp_bot":  handle_whatsapp_bot,
    "email_alert":   handle_email_alert,
}

def process_message(msg: dict):
    body = json.loads(msg['Body'])
    task_type = body.get('task_type')
    payload   = body.get('payload', {})
    handler   = HANDLERS.get(task_type)
    if handler:
        handler(payload)
    else:
        logger.warning("Unknown task_type: %s", task_type)

def run():
    if not QUEUE_URL or QUEUE_URL == 'your_queue_url':
        logger.error("SQS_QUEUE_URL not configured. Set it in .env and restart.")
        return
    if not os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('AWS_ACCESS_KEY_ID') == 'your_aws_access_key':
        logger.error("AWS credentials not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env")
        return
    sqs = _sqs()
    logger.info("Consumer started. Polling %s", QUEUE_URL)
    consecutive_errors = 0
    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=POLL_WAIT,
                MessageAttributeNames=['All'],
            )
            consecutive_errors = 0
            messages = resp.get('Messages', [])
            for msg in messages:
                try:
                    process_message(msg)
                    sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=msg['ReceiptHandle'])
                    logger.info("Message processed and deleted")
                except Exception as e:
                    logger.error("Handler error (will retry via SQS): %s", e)
        except (BotoCoreError, ClientError) as e:
            consecutive_errors += 1
            logger.error("SQS poll error: %s", e)
            if consecutive_errors >= 3:
                logger.error("Too many consecutive errors. Check AWS credentials in .env. Exiting.")
                return
            time.sleep(5)

if __name__ == '__main__':
    run()
