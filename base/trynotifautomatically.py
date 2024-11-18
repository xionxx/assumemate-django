# send_notification.py

import firebase_admin
from firebase_admin import credentials, messaging

# Initialize Firebase Admin SDK with your Firebase Admin SDK JSON file
cred = credentials.Certificate('path/to/messagetrial1-firebase-adminsdk-omyr6-845be3ae18.json')  # Replace with the actual JSON path
firebase_admin.initialize_app(cred)

def send_fcm_notification(fcm_token, title, body):
    """
    Sends an FCM notification to the given token with the provided title and body.
    """
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body
        ),
        token=fcm_token
    )

    try:
        # Send the message
        response = messaging.send(message)
        print('Successfully sent message:', response)
        return response
    except Exception as e:
        print('Error sending message:', e)
        return None
