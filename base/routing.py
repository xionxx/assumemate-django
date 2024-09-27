from django.urls import re_path
from base import consumers

websocket_urlpatterns = [ re_path(r'ws/socket-server/', consumers.ChatConsumer.as_asgi()), ]