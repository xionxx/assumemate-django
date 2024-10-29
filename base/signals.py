from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import ChatRoom
import json

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

@receiver(post_save, sender=ChatRoom)
def update_message_read(sender, instance, created, **kwargs):
    if not created:
        channel_layer = get_channel_layer()
        chatroom = instance.chat_room
        is_seen = instance.is_read

        data = {
            'chat_room':chatroom,
            'chat_status':is_seen
        }
        async_to_sync(
            channel_layer.group_send)(
            'user', {
                'type':'chat_status',
                'value':json.dumps(data)
            }
        )
