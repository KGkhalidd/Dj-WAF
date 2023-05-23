from main.models import Blockedclient
import os
import django
# Set environment variable > Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'waf.settings')
django.setup()


def get_blocked_ips():
    blocked_ips = Blockedclient.objects.values_list('client_ip', flat=True)
    return blocked_ips


print(list(get_blocked_ips()))
