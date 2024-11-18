import base64
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import  permissions, status
from rest_framework.response import Response
import requests
import os
from .models import *
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from dotenv import load_dotenv

load_dotenv()
UserModel = get_user_model()

client_id = os.getenv('PARTNER_CLIENT_ID')
secret_key = os.getenv('PARTNER_SECRET_KEY')
baseURL = os.getenv('PAYPAL_BASE_URL')


def get_paypal_access_token():
    url = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
    headers = {"Accept": "application/json", "Accept-Language": "en_US"}
    auth = (client_id, secret_key)
    data = {"grant_type": "client_credentials"}

    response = requests.post(url, headers=headers, auth=auth, data=data)
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

        response = requests.post(f'{baseURL}/v2/customer/partner-referrals', headers=headers, json=data)
        print(response.json())

        response = response.json()
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

        # amount = request.data.get('amount', '10.00')

        id
        user = request.user
        offer_id = request.data.get('offer_id')
        offer = Offer.objects.get(offer_id=offer_id)
        amount = offer.offer_price
        list_id = offer.list_id

        print(offer_id)

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
            if OrderListing.objects.filter(list_id=list_id, order_status='PENDING'):
                return Response({'error': 'There is an existing order for this listing'}, status=status.HTTP_400_BAD_REQUEST)
            
            response = requests.post(url, json=order_data, headers=auth_header)
            response.raise_for_status()
            
            order_data = response.json()

            OrderListing.objects.create(order_price=amount, offer_id=offer, list_id=list_id, user_id=user)
            
            print(order_data)
            print(order_data['id'])

            return Response({
                'order_id': order_data['id'],
                'approval_url': next(link['href'] for link in order_data['links'] if link['rel'] == 'approve')
            })
        
        except requests.exceptions.RequestException as e:
            print(e)
            return Response({'error': 'Unable to create PayPal order'}, status=500)