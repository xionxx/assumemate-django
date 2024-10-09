# middleware.py

import jwt
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()

class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        # Get the token from the query string
        token = None
        if 'query_string' in scope:
            query_string = scope['query_string'].decode()
            if 'token=' in query_string:
                token = query_string.split('token=')[-1]

        # If a token is found, authenticate the user
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload['user_id']
                scope['user'] = await self.get_user(user_id)
            except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
                scope['user'] = None

        return await super().__call__(scope, receive, send)

    @database_sync_to_async
    def get_user(self, user_id):
        return User.objects.get(id=user_id)
