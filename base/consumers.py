import locale
import uuid
from django.utils import timezone
import json
from django.db.models import Q
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
import requests, base64, cloudinary
from django.core.files.base import ContentFile
from .models import ChatRoom, ChatMessage, Offer, Listing

from django.contrib.auth import get_user_model
UserModel = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']

        if not self.user.is_authenticated:
            await self.close()
            return
            
        self.other_user_id = self.scope['url_route']['kwargs']['receiver_id']
        if int(self.user.id) > int(self.other_user_id):
            self.room_name = f'{self.user.id}-{self.other_user_id}'
        else:
            self.room_name = f'{self.other_user_id}-{self.user.id}'


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
        roomId = data.get('room_id')

        if message_type == 'message':
            message = data['message']

            text = message.get('message')
            file = message.get('file')
            file_type = message.get('file_type')
            file_name = message.get('file_name')

            last_message = ''
            file_url = ''
            messages = {
                'text': text,
                'file': None,
                'file_type': file_type
            }

            if file:
                try:
                    decoded_file = base64.b64decode(file)
                    image_data = ContentFile(decoded_file, name=f"{file_name}{file_type}")

                    
                    resource_type = 'raw' if file_type in ['.pdf', '.doc', '.docx'] else 'auto'
                    
                    upload_result = cloudinary.uploader.upload(image_data, folder=f"user_file_photo/room_{roomId}", public_id=file_name, resource_type=resource_type)

                    file_url = upload_result['secure_url'] if upload_result else None
                    messages['file'] = file_url
                except Exception as e:
                    print(f"Error uploading file: {e}")
                    messages['file'] = None

            if text:
                if file_type in ['.jpg', '.jpeg', '.png']:
                    messages['file_type'] = 'image'
                    last_message = f'Sent a photo: {text}'
                elif file_type in ['.pdf', '.doc', '.docx']:
                    messages['file_type'] = 'document'
                    last_message = f'Sent a file: {text}'
                else:
                    last_message = text
            else:
                if file_type in ['.jpg', '.jpeg', '.png']:
                    messages['file_type'] = 'image'
                    last_message = f'Sent a photo.'
                elif file_type in ['.pdf', '.doc', '.docx']:
                    messages['file_type'] = 'document'
                    last_message = f'Sent a file.'

            await self.save_chat_room(user_id, self.other_user_id)
            room_id = await self.save_message(user_id, messages, self.other_user_id)
            await self.chatroom_last_message(user_id, last_message, room_id)

            is_read = False
            timestamp = timezone.now().isoformat()

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': messages,
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

            messages = {
                'text': message,
                'file': None,
                'file_type': None
            }

            await self.update_offer(offer_id, offer_status)
            await self.save_chat_room(user_id, self.other_user_id)
            room_id = await self.save_message(user_id, messages, self.other_user_id)
            await self.chatroom_last_message(user_id, message, room_id)
            is_read = False
            timestamp = timezone.now().isoformat()

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'offer_status',
                    'message': messages,
                    'user_id': user_id,
                    'timestamp': timestamp,
                    'isRead': is_read,
                    'offer_id': offer_id,
                    'offer_status': offer_status
                }
            )

        elif message_type == 'change_offer_amount':
            offer_id = data['offer_id']
            offer_amount = data['offer_amount']
            user_id = data['user_id']

            locale.setlocale(locale.LC_ALL, 'en_PH.UTF-8')
            # double_amnt = double
            formatted_amount = locale.currency(float(offer_amount), grouping=True)

            print(formatted_amount)

            message = f'Change offer: {formatted_amount}'

            messages = {
                'text': message,
                'file': None,
                'file_type': None
            }
            
            await self.change_offer_amount(offer_id, offer_amount)
            await self.save_chat_room(user_id, self.other_user_id)
            room_id = await self.save_message(user_id, messages, self.other_user_id)
            await self.chatroom_last_message(user_id, message, room_id)
            is_read = False
            timestamp = timezone.now().isoformat()

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'change_offer',
                    'message': messages,
                    'user_id': user_id,
                    'timestamp': timestamp,
                    'isRead': is_read,
                    'offer_id': offer_id,
                    'offer_amount': offer_amount
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

    async def change_offer(self, event):
        user_id = event['user_id']
        offer_id = event['offer_id']
        offer_amount = event['offer_amount']
        message = event['message']
        timestamp = event['timestamp']
        is_read = event['isRead']

        await self.send(text_data=json.dumps({
            'type': 'change_offer',
            'message': message,
            'user_id': user_id,
            'timestamp': timestamp,
            'is_read': is_read,
            'offer_id': offer_id,
            'offer_amount': offer_amount
        }))

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
        try:
            offer = Offer.objects.get(offer_id=offer_id)

            list_id = offer.list_id
            try:
                list_id = str(list_id)
                listing = Listing.objects.get(list_id=list_id)
                
                if offer_status == 'ACCEPTED':
                    listing.list_status = 'RESERVED'

                    other_offers = Offer.objects.filter(list_id=list_id).exclude(offer_id=offer_id)
                    for other_offer in other_offers:
                        other_offer.offer_status = 'REJECTED'
                        other_offer.save()

                        message = f'Offer rejected'

                        messages = {
                            'text': message,
                            'file': None,
                            'file_type': None
                        }

                        self.save_message(self.user.id, messages, other_offer.user_id.id)

                elif offer_status == 'CANCELLED':
                    listing.list_status = 'ACTIVE'
                
                listing.save()
            except Listing.DoesNotExist:
                raise ValueError("Listing does not exist")
        
            
            offer.offer_status = offer_status
            offer.offer_updated_at = timezone.now
            offer.save()

        except Offer.DoesNotExist:
            raise ValueError("Offer does not exist")

    @database_sync_to_async
    def change_offer_amount(self, offer_id, offer_amnt):
        try:
            offer = Offer.objects.get(offer_id=offer_id)

            if offer.offer_status != 'PENDING':
                return ValueError('Cannot change offer amount')
            
            offer.offer_price = offer_amnt
            offer.offer_updated_at = timezone.now
            offer.save()
        except Offer.DoesNotExist:
            raise ValueError("Offer does not exist")

class MessageIsReadConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']

        if not self.user.is_authenticated:
            await self.close()
            return
        
        self.chatroom = self.scope['url_route']['kwargs']['room_id']

        self.room_group_name = f'room_{self.chatroom}'

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
        try:
            data = json.loads(text_data)
            chat_room = data['chat_room']
            chat_status = data['chat_status']
            user_id = data['user_id']

            if chat_room != self.chatroom:
                    await self.send(text_data=json.dumps({'error': 'Invalid chat room ID'}))
                    return

            await self.update_message_isRead(chat_room, user_id)

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_status',
                    'user_id': user_id,
                    'chat_room': chat_room,
                    'chat_status': chat_status
                }
            )
        except Exception as e:
            await self.send(text_data=json.dumps({'error': str(e)}))

    async def chat_status(self, event):
        chat_room = event['chat_room']
        chat_status = event['chat_status']
        user_id = event['user_id']

        await self.send(text_data=json.dumps({
            'type': 'chat_status',
            'user_id': user_id,
            'chat_room': chat_room,
            'chat_status': chat_status
        }))

    @database_sync_to_async
    def update_message_isRead(self, room_id, sender):
        hasUpdate=ChatMessage.objects.filter(Q(chatroom_id=room_id) & ~Q(sender_id=sender) & Q(chatmess_is_read=False)).update(chatmess_is_read=True)
        
        print(f'Updated {hasUpdate} messages as read in room {room_id}.')

        # return hasUpdate

class InboxConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']

        if not self.user.is_authenticated:
            await self.close()
            return
        
        self.room_name = f'user_{self.user.id}'
        
        await self.channel_layer.group_add(
            self.room_name,
            self.channel_name
        )

        await self.accept()
    
    async def disconnect(self, code):
        await self.channel_layer.group_discard(
            self.room_name,
            self.channel_name
        )

    async def receive(self, text_data=None):
        data = json.loads(text_data)
        type = data['type']

        if type == 'inbox_update':
            sender_id = data['sender_id']
            message = data['message']
            roomId = data['room_id']
            chatmate_id = data['receiver_id']
            is_read = data['is_read']

            for user_id in (self.user.id, chatmate_id):
                print(user_id)
                await self.channel_layer.group_send(
                    f'user_{user_id}',
                    {
                        'type': 'inbox_update',
                        'message': message,
                        'room_id': roomId,
                        'sender_id': sender_id,
                        'is_read': is_read
                    }
                )

        elif type == 'inbox_read':
            roomId = data['room_id']
            is_read = data['is_read']

            await self.channel_layer.group_send(
            self.room_name,
            {
                'type': 'inbox_read',
                'room_id': roomId,
                'is_read': is_read
            }
        )

    async def inbox_update(self, event):
        room_id = event['room_id']
        message = event['message']
        sender_id = event['sender_id']
        is_read = event['is_read']
        
        
        text = message.get('message')
        file_type = message.get('file_type')

        last_message = ''

        if text:
            if file_type in ['.jpg', '.jpeg', '.png']:
                last_message = f'Sent a photo: {text}'
            elif file_type in ['.pdf', '.doc', '.docx']:
                last_message = f'Sent a file: {text}'
            else:
                last_message = text
        else:
            if file_type in ['.jpg', '.jpeg', '.png']:
                last_message = f'Sent a photo.'
            elif file_type in ['.pdf', '.doc', '.docx']:
                last_message = f'Sent a file.'

        timestamp = timezone.now().isoformat()

        await self.send(text_data=json.dumps({
            'type': 'inbox_update',
            'message': last_message,
            'room_id': room_id,
            'sender_id': sender_id,
            'timestamp': timestamp,
            'isRead': is_read
        }))

    async def inbox_read(self, event):
        room_id = event['room_id']
        is_read = event['is_read']

        await self.send(text_data=json.dumps({
            'type': 'inbox_read',
            'room_id': room_id,
            'isRead': is_read
        }))