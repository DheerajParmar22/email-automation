from django.shortcuts import redirect, render
from django.http import HttpResponse
from google_auth_oauthlib.flow import InstalledAppFlow
from .utils import get_gmail_auth_url, get_gmail_service, save_gmail_credentials
from .tasks import check_emails

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send']

def index(request):
    return render(request, 'index.html')

def connect_gmail(request):
    auth_url = get_gmail_auth_url()
    return redirect(auth_url)

def gmail_callback(request):
    code = request.GET.get('code')
    if code:
        handle_gmail_callback(code)
        # trigger_email_processing(request)
        return render(request, 'connected.html', {'service': 'Gmail'})
    else:
        return HttpResponse('Authorization code not found', status=400)

def handle_gmail_callback(code):
    flow = InstalledAppFlow.from_client_secrets_file('email_app\client_secret_168879313172-ob1cr7fim197m7t9p3vfjpaeoqkmh6at.apps.googleusercontent.com.json', SCOPES,redirect_uri='http://localhost:8000/gmail_callback/')
    flow.fetch_token(code=code)
    creds = flow.credentials
    save_gmail_credentials(creds)

def trigger_email_processing(request):
    check_emails()
    return HttpResponse("Email processing triggered.")

# def connect_outlook(request):
#     auth_url = get_outlook_auth_url()
#     return redirect(auth_url)

# def outlook_callback(request):
#     device_code = request.GET.get('device_code')
#     handle_outlook_callback(device_code)  # Implement handle_outlook_callback function
#     return render(request, 'connected.html', {'service': 'Outlook'})

# def handle_outlook_callback(device_code):
#     token = get_outlook_token(device_code)
#     # Handle Outlook OAuth callback and save token
