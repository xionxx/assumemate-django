import os
import requests
import firebase_admin
from firebase_admin import credentials, messaging
from django.conf import settings


cred_path = os.path.join(settings.BASE_DIR, "static_files/json/messagetrial1-firebase-adminsdk-omyr6-80a1d4544a.json")


try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        print("Firebase Admin SDK initialized successfully")
except Exception as e:
    print(f"Error initializing Firebase: {e}")

def get_access_token():
    """
    Get a valid access token for Firebase.
    """
    try:
        app = firebase_admin.get_app()
        cred = app.credential
        token = cred.get_access_token()
        return token.access_token
    except Exception as e:
        print(f"Error getting access token: {e}")
        return None

def send_push_notification(fcm_token, title, body, image_url=None, data_payload=None):
    """
    Send a push notification using Firebase Cloud Messaging (FCM) HTTP v1 API.
    Supports optional image URL and flexible data payload for custom routing.
    """
    try:
        # Get access token
        access_token = get_access_token()
        if not access_token:
            raise Exception("Failed to get access token")

        # Construct the message payload
        message = {
            "message": {
                "token": fcm_token,
                "notification": {
                    "title": title,
                    "body": body,
                    "image": image_url or ''  # Add image URL if provided
                },
                "android": {
                    "priority": "high",
                    "notification": {
                        "sound": "default",
                        "channel_id": "default",
                        "image": image_url  # Android-specific image URL
                    }
                },
                "apns": {
                    "payload": {
                        "aps": {
                            "sound": "default",
                            "content-available": 1,
                            "mutable-content": 1
                        }
                    },
                    "fcm_options": {
                        "image": image_url  # APNS-specific image URL
                    }
                },
                # Add custom data payload, defaulting to an empty dictionary if none provided
                "data": data_payload or {}
            }
        }

        # FCM endpoint for HTTP v1
        project_id = "messagetrial1"  # Your project ID
        url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        print("Push Notification Payload: ", message)
        # Send the message via Firebase Cloud Messaging
        response = requests.post(url, headers=headers, json=message)

        # Check the response
        if response.status_code == 200:
            print("Notification sent successfully!")
            return True
        else:
            print(f"Failed to send notification: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        print(f"Error sending notification: {e}")
        return False

def debug_fcm_setup():
    """
    Debug Firebase setup to check if the app is initialized properly.
    """
    try:
        # Test Firebase initialization
        app = firebase_admin.get_app()
        print("Firebase app initialized:", bool(app))

        return {
            "firebase_initialized": bool(app),
            "project_id": "messagetrial1"
        }
    except Exception as e:
        return {
            "error": str(e),
            "firebase_initialized": False
        }
