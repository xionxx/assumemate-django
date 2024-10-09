from django.urls import re_path
from base import consumers

websocket_urlpatterns = [ 
    re_path(r'ws/chat/(?P<receiver_id>\d+)/$', consumers.ChatConsumer.as_asgi()), 
    re_path(r'ws/chat/inbox/$', consumers.InboxConsumer.as_asgi()), 
    ]