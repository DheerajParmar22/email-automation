import os
from django_rq import job
# from bullmq import Queue
# from huey.contrib.djhuey import periodic_task, task
# from huey import RedisHuey
# from background_task import background
from .utils import categorize_email, generate_response, send_email, get_gmail_service, get_emails


@job
def process_email(email):
    try:
        from_address = email.get('from')
        content = email.get('content')
        
        if not from_address or not content:
            raise ValueError("Missing 'from' or 'content' in email")

        category = categorize_email(content)
        reply = generate_response(content, category)
        send_email(from_address, reply)
    except KeyError as e:
        print(f"KeyError: {e}")
    except Exception as e:
        print(f"Error processing email: {e}")


def check_emails():
    gmail_service = get_gmail_service()
    emails = get_emails(gmail_service)
    for email in emails:
        process_email(email)