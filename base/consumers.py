from channels.generic.websocket import WebsocketConsumer
import json

class ChatConsumer(WebsocketConsumer):
    async def connect(self):
        await self.accept()
        # Optionally join a room or send a welcome message
        await self.send(text_data=json.dumps({
            'message': 'You are now connected!'
        }))

    async def disconnect(self, close_code):
        # Handle disconnection
        pass

    async def receive(self, text_data):
        # Handle incoming messages
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))