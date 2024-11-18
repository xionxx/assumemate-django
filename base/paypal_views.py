import base64
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import  permissions, status
from django.db import transaction
from rest_framework.response import Response
import requests as req
import os
from .models import *
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from dotenv import load_dotenv

load_dotenv()
UserModel = get_user_model()

client_id = os.getenv('PAYPAL_CLIENT_ID')
secret_key = os.getenv('PAYPAL_CLIENT_SECRET')
baseURL = os.getenv('PAYPAL_BASE_URL')


def get_paypal_access_token():
    url = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
    headers = {"Accept": "application/json", "Accept-Language": "en_US"}
    auth = (client_id, secret_key)
    data = {"grant_type": "client_credentials"}

    response = req.post(url, headers=headers, auth=auth, data=data)
    response.raise_for_status()
    return response.json().get("access_token")

class PaypalOnboard(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        baseUrl = os.getenv('API_URL')
        assumptor_id = request.user.id
        email = request.user.email

        access = get_paypal_access_token()
        print('access')

        print(access)
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access}',
            "Accept": "application/json"
        }
        

        data ={ "email": email,
            "tracking_id": f"{assumptor_id}",
            "partner_config_override": {
                "return_url": f"http://{baseUrl}/user/onboarded/",
                "return_url_description": "the url to return the merchant after the paypal onboarding process.",
                "show_add_credit_card": False
            },
            "operations": [
                {
                    "operation": "API_INTEGRATION",
                    "api_integration_preference": {
                        "rest_api_integration": {
                            "integration_method": "PAYPAL",
                            "integration_type": "THIRD_PARTY",
                            "third_party_details": {
                                "features": [
                                    "PAYMENT",
                                    "REFUND",
                                    "PARTNER_FEE"
                                ]
                            }
                        }
                    }
                }
            ],
            "products": [
                "PAYMENT_METHODS"
            ],
            "capabilities": [
                "APPLE_PAY"
            ],
            "legal_consents": [
                {
                    "type": "SHARE_DATA_CONSENT",
                    "granted": True
                }
            ]
        }

        response = req.post(f'{baseURL}/v2/customer/partner-referrals', headers=headers, json=data)
        print(response.json())

        response = response.json()
        print(response)
        onboarding_url = response["links"][1]["href"]
        partner_id = onboarding_url.split("token=")[-1]
        print(partner_id)
        return Response({"onboarding_url": onboarding_url})
    
class CreatePaypalOrder(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        access = get_paypal_access_token()
        print(access)
        url = f"{baseURL}/v2/checkout/orders"
        auth_header = {
            "Authorization": f"Bearer {access}",
            "Content-Type": "application/json"
        }

        amount = request.data.get('amount', '10.00')

        # user = request.user
        # data = request.data.get('order_id')

        # if 'order_id' in data:
        #     order_id = data.get('order_id')

        #     order = OrderListing.objects.get(order_id=order_id)
            
        #     amount = order.order_price

        order_data = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": {
                    "currency_code": "PHP",
                    "value": str(amount),
                }
            }],

            "application_context": {
                "return_url": "http://yourapp.com/payment-success",
                "cancel_url": "http://yourapp.com/payment-cancelled",
                "user_action": "PAY_NOW",
                "shipping_preference": "NO_SHIPPING",
            }
        }

        try:
            
            response = req.post(url, json=order_data, headers=auth_header)
            response.raise_for_status()
            
            order_data = response.json()
            
            print(order_data)
            print(order_data['id'])

            return Response({
                'paypal_order_id': order_data['id'],
                'approval_url': next(link['href'] for link in order_data['links'] if link['rel'] == 'approve')
            })
        
        except req.exceptions.RequestException as e:
            print(e)
            return Response({'error': 'Unable to create PayPal order'}, status=500)
        
class CapturePaypalOrder(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        access = get_paypal_access_token()
        print(access)

        data = request.data

        trans_type = data.get('trans_type')
        paypal_order_id = data.get('paypal_order_id')

        if not paypal_order_id:
            return Response({'error': 'Missing orderID'}, status=400)
        
        # order_id = None

        # if 'order_id' in data:
        order_id = data.get('order_id')
        print(order_id)

        capture_url = f"{baseURL}/v2/checkout/orders/{paypal_order_id}/capture"
        auth_header = {
            "Authorization": f"Bearer {access}",
            "Content-Type": "application/json"
        }

        try:
            with transaction.atomic():
                order = None
                if order_id:
                    try:
                        order = OrderListing.objects.get(order_id=order_id)
                        order.order_status = 'PAID'
                        order.save()

                        if order.offer_id:
                            order.offer_id.offer_status = 'PAID'
                            order.offer_id.save()
                    except OrderListing.DoesNotExist:
                        return Response({'error': 'Order not found'}, status=404)
                    
                capture_response = req.post(capture_url, headers=auth_header)
                capture_response.raise_for_status()
                
                capture_data = capture_response.json()
                print(capture_data)
                
                # Extract capture details from the response
                capture_id = capture_data['purchase_units'][0]['payments']['captures'][0]['id']
                capture_amount = capture_data['purchase_units'][0]['payments']['captures'][0]['amount']['value']
                # Retrieve the UserAccount instance associated with the currently authenticated user
                user_account = request.user

                # Create a new transaction and link it to the logged-in user
                new_transaction = Transaction.objects.create(
                    transaction_paypal_order_id=paypal_order_id,
                    transaction_paypal_capture_id=capture_id,
                    transaction_amount=capture_amount,
                    user_id=user_account,  
                    transaction_type=trans_type,
                    order_id=order
                )

                return Response({
                    'status': 'COMPLETED',
                    'paypal_order_id': paypal_order_id,
                    'capture_id': capture_id,
                    'amount': capture_amount,
                    'transaction_id': new_transaction.transaction_id  # Return the transaction ID for reference
                })
        
        except req.exceptions.RequestException as e:
            print(f"PayPal capture error: {str(e)}")
            return Response({'error': 'Payment capture failed'}, status=500)
        
class PaypalPaymentCancelled(APIView):
        def get(self, request, *args, **kwargs):
                # You can handle cancellation logic here, such as notifying the user
                return JsonResponse({'status': 'Payment cancelled'})