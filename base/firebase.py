# import firebase_admin
# from firebase_admin import credentials, messaging
# import os



# cred_path = 'D:\\django\\Assumemate\\Assumemate\\Assumemate\\base\\config\\pushnotification-5372d-firebase-adminsdk-qh1qj-f373e563eb.json'

# cred = credentials.Certificate(cred_path)

# firebase_admin.initialize_app(cred)

# def send_push_notification(token, title, body, data=None):
#     message = messaging.Message(
#         notification=messaging.Notification(
#             title=title,
#             body=body,
#         ),
#         data=data,  
#         token=token,
#     )
    
#     response = messaging.send(message)
#     print('Successfully sent message:', response)
