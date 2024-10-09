from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import ChatRoom
import json

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

@receiver(post_save, sender=ChatRoom)
def update_inbox(sender, instance, created, **kwargs):
    if created:
        channel_layer = get_channel_layer()
        inbox_obj = ChatRoom

