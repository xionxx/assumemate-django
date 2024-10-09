from django.utils import timezone
import json
from django.db.models import Q
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import ChatRoom, ChatMessage, Offer

from django.contrib.auth import get_user_model
UserModel = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope['user']

        if not user.is_authenticated:
            await self.close()
            return
            
        self.other_user_id = self.scope['url_route']['kwargs']['receiver_id']
        if int(user.id) > int(self.other_user_id):
            self.room_name = f'{user.id}-{self.other_user_id}'
        else:
            self.room_name = f'{self.other_user_id}-{user.id}'


        self.room_group_name = 'chat_%s' % self.room_name

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data=None):
        data = json.loads(text_data)
        print(data)
        user_id = data['user_id']
        message_type = data.get('type')

        if message_type == 'message':
            message = data['message']

            await self.save_chat_room(user_id, self.other_user_id)
            room_id = await self.save_message(user_id, message, self.other_user_id)
            await self.chatroom_last_message(user_id, message, room_id)
            is_read = False
            timestamp = timezone.now().isoformat()

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message,
                    'user_id': user_id,
                    'timestamp': timestamp,
                    'isRead': is_read
                }
        )
        
        elif message_type == 'typing':
            user_id = data['user_id']
            typing = data['is_typing'] 

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'typing_status',
                    'user_id': user_id,
                    'is_typing': typing,
                }
            )

        elif message_type == 'offer_update':
            offer_id = data['offer_id']
            offer_status = data['offer_status']
            user_id = data['user_id']

            oStatus = offer_status.lower()

            message = f'Offer {oStatus}'

            await self.update_offer(offer_id, offer_status)
            await self.save_chat_room(user_id, self.other_user_id)
            room_id = await self.save_message(user_id, message, self.other_user_id)
            await self.chatroom_last_message(user_id, message, room_id)
            is_read = False
            timestamp = timezone.now().isoformat()

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'offer_status',
                    'message': message,
                    'user_id': user_id,
                    'timestamp': timestamp,
                    'isRead': is_read,
                    'offer_id': offer_id,
                    'offer_status': offer_status
                }
            )

    async def chat_message(self, event):
        user_id = event['user_id']
        message = event['message']
        timestamp = event['timestamp']
        is_read = event['isRead']

        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'user_id': user_id,
            'message': message,
            'timestamp': timestamp,
            'is_read': is_read,
        }))

    async def typing_status(self, event):
        user_id = event['user_id']
        is_typing = event['is_typing']

        await self.send(text_data=json.dumps({
            'type': 'typing_status',
            'user_id': user_id,
            'is_typing': is_typing,
        }))

    async def offer_status(self, event):
        user_id = event['user_id']
        offer_id = event['offer_id']
        offer_status = event['offer_status']
        message = event['message']
        timestamp = event['timestamp']
        is_read = event['isRead']

        await self.send(text_data=json.dumps({
            'type': 'offer_status',
            'message': message,
            'user_id': user_id,
            'timestamp': timestamp,
            'is_read': is_read,
            'offer_id': offer_id,
            'offer_status': offer_status
        }))

    async def update_offer_amount(self, event):
        user_id = event['user_id']
        offer_id = event['offer_id']
        offer_status = event['offer_status']
        message = event['message']
        timestamp = event['timestamp']
        is_read = event['isRead']

    @database_sync_to_async
    def save_chat_room(self, user_1, user_2):
        if int(user_1) > int(user_2):
            user1 = UserModel.objects.get(id=user_1)
            user2 = UserModel.objects.get(id=user_2)
        else:
            user2 = UserModel.objects.get(id=user_1)
            user1 = UserModel.objects.get(id=user_2)

        if not ChatRoom.objects.filter(Q(chatroom_user_1=user1, chatroom_user_2=user2)).exists():
            ChatRoom.objects.create(
                chatroom_user_1=user1, chatroom_user_2=user2
            )

    @database_sync_to_async
    def save_message(self, user_id, message, receiver_id):
        if int(user_id) > int(receiver_id):
            user1 = UserModel.objects.get(id=user_id)
            user2 = UserModel.objects.get(id=receiver_id)
        else:
            user2 = UserModel.objects.get(id=user_id)
            user1 = UserModel.objects.get(id=receiver_id)

        room_id = ChatRoom.objects.get(Q(chatroom_user_1=user1, chatroom_user_2=user2))
        user = UserModel.objects.get(id=int(user_id))

        ChatMessage.objects.create(
            sender_id=user, chatmess_content=message, chatroom_id=room_id)
        
        print(room_id)
        
        return room_id.chatroom_id
        
    @database_sync_to_async
    def chatroom_last_message(self, user_id, message, room_id):
        room = ChatRoom.objects.get(chatroom_id=room_id)
        user = UserModel.objects.get(id=int(user_id))

        room.chatroom_last_message = message
        # room.user_id = user
        room.save()
    
    @database_sync_to_async
    def update_offer(self, offer_id, offer_status):
        offer = Offer.objects.get(offer_id=offer_id)

        offer.offer_status = offer_status
        offer.save()

    async def inbox_update(self, event):
        user_id = event['user_id']
        message = event['message']
        timestamp = event['timestamp']
        is_read = event['isRead']

        await self.send(text_data=json.dumps({
            'type': 'inbox_update',
            'user_id': user_id,
            'message': message,
            'timestamp': timestamp,
            'is_read': is_read,
        }))

class InboxConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user_id = self.scope['user']
        self.inbox_group_name = f'inbox_{self.user_id.id}'

        # Join inbox group for the user
        await self.channel_layer.group_add(
            self.inbox_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.inbox_group_name,
            self.channel_name
        )

    async def inbox_update(self, event):
        user_id = event['user_id']
        message = event['message']
        timestamp = event['timestamp']
        is_read = event['isRead']

        await self.send(text_data=json.dumps({
            'type': 'inbox_update',
            'user_id': user_id,
            'message': message,
            'timestamp': timestamp,
            'is_read': is_read,
        }))
