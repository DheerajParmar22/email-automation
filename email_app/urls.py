from django.urls import path
from .views import index, connect_gmail, gmail_callback, trigger_email_processing

urlpatterns = [
    path('', index, name='index'),
    path('connect_gmail/', connect_gmail, name='connect_gmail'),
    path('gmail_callback/', gmail_callback, name='gmail_callback'),
    path('trigger-email-processing/', trigger_email_processing, name='trigger_email_processing'),
]
