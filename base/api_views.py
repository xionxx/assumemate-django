from decimal import ROUND_DOWN, Decimal
import json
import locale
import random
from django.forms import ValidationError
from django.shortcuts import redirect, render
from django.urls import reverse
import requests as req
import base64
import cloudinary
from smtplib import SMTPConnectError, SMTPException
# from django.contrib.auth.decorators import user_passes_test
from django.utils import timezone
from django.http import Http404, HttpResponseRedirect, JsonResponse
from django.db.models import F, Max, OuterRef, Subquery, Case, When, Count, Avg
# from .permissions import IsAdminUser
from .models import UserProfile, UserVerification, ChatRoom, ChatMessage, Wallet, ListingApplication
from .serializers import *
from rest_framework import status, permissions, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.files.base import ContentFile
from rest_framework.authtoken.models import Token
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from django.contrib.auth import login as login, logout
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import update_last_login
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from google.oauth2 import id_token as token_auth
from google.auth.transport import requests
import logging

logger = logging.getLogger(__name__)

load_dotenv()

clientId = os.getenv('PAYPAL_CLIENT_ID')
secretKey = os.getenv('PAYPAL_CLIENT_SECRET')
baseURL = os.getenv('PAYPAL_BASE_URL')

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class UserRegister(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            serializer = UserRegisterSerializer(data=request.data)
            profile = request.data.get('profile')
            user_picture = profile['user_prof_valid_pic']
            user_valid_id = profile['user_prof_valid_id']

            print(user_valid_id)
            if not user_valid_id or not user_picture:
                return Response({'error': 'No valid ID or picture provided'}, status=status.HTTP_400_BAD_REQUEST)
            
            if serializer.is_valid(raise_exception=False):
                # deets = serializer.data
                user = serializer.save()


                print(user)

                # user_prof = user_data['profile']
                # user_deet = user_data['profile']
                profile = UserProfile.objects.get(user_id=user.id)

                images = [user_valid_id, user_picture]
                folder_name = f"{profile.user_prof_fname} {profile.user_prof_lname} ({profile.user_id})"

                uploaded_images = []
                
                try:
                    for img in images:
                        # format, imgstr = img.split(';base64,') 
                        ext = 'jpg'
                        
                        image_data = ContentFile(base64.b64decode(img), name=f"user{profile.user_id}_{profile.user_prof_fname}_{profile.user_prof_lname}.{ext}")

                        upload_result = cloudinary.uploader.upload(image_data, folder=f"user_images/{folder_name}")

                        uploaded_images.append(upload_result['secure_url'] if image_data else None)

                    if len(uploaded_images) == 2:
                        profile.user_prof_valid_id = uploaded_images[0]
                        profile.user_prof_valid_pic = uploaded_images[1]
                    else:
                        return JsonResponse({'error': 'Image upload failed.'}, status=status.HTTP_400_BAD_REQUEST)
                    
                    profile.save()

                    
                except Exception as e:
                    return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
                

                user_data = UserRegisterSerializer(user).data
                print(user_data)

                refresh_token = RefreshToken.for_user(user)
                access_token = str(refresh_token.access_token)
                
                return Response({'access': access_token, 'refresh': str(refresh_token), 'user': user_data}, status=status.HTTP_201_CREATED)
            
            # print(serializer.errors)
            # errors = serializer.errors
            # profile_errors = errors.get('profile', {})
            # non_field_errors = profile_errors.get('non_field_errors', [])
            
            # print("Errors:", non_field_errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': f'{e}'})

class UserCreateProfile(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        data = request.data
        print(data)
        serializer = UserProfileSerializer(data=data)
        user_valid_id = request.data.get('user_prof_valid_id')
        user_picture = request.data.get('user_prof_valid_pic')

        if serializer.is_valid(raise_exception=True):
            user = UserModel.objects.get(id=data['user_id'])
            user_profile = serializer.save(user_id=user)

            user = user_profile.user_id

            if not user_valid_id or not user_picture:
                return Response({'error': 'No valid ID or picture provided'}, status=status.HTTP_400_BAD_REQUEST)
            
            images = [user_valid_id, user_picture]
            folder_name = f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} ({user.id})"

            uploaded_images = []
            
            try:
                for img in images:
                    # format, imgstr = img.split(';base64,') 
                    ext = 'jpg'
                    
                    image_data = ContentFile(base64.b64decode(img), name=f"user{user.id}_{user_profile.user_prof_fname}_{user_profile.user_prof_lname}.{ext}")

                    upload_result = cloudinary.uploader.upload(image_data, folder=f"user_images/{folder_name}")

                    uploaded_images.append(upload_result['secure_url'] if image_data else None)

                if len(uploaded_images) == 2:
                    user_profile.user_prof_valid_id = uploaded_images[0]
                    user_profile.user_prof_valid_pic = uploaded_images[1]
                else:
                    return JsonResponse({'error': 'Image upload failed.'}, status=status.HTTP_400_BAD_REQUEST)
                
                user_profile.save()

            except Exception as e:
                return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
            
            refresh_token = RefreshToken.for_user(user)
            access_token = str(refresh_token.access_token)

            UserApplication.objects.create(user_id=user)
            
            reserializer = UserProfileSerializer(user_profile)
            return Response({'access': access_token, 'refresh': str(refresh_token), 'user_profile': reserializer.data}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserEmailVerification(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        email = request.data.get('user_verification_email')
        existing_record = serializer.check_email(email=email)
        if existing_record:
            try:
                serializer.send_verification_email(request, existing_record.user_verification_email, existing_record.user_verification_code)
            except SMTPConnectError:
                return Response(
                    {'error': 'Unable to connect to the email server. Please try again later.'},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE
                        )
            except SMTPException as e:
                return Response({'error': 'Error sending verification code.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except requests.exceptions.ConnectionError:
                return Response({'error': 'Connection error. Please try again.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            return Response(EmailVerificationSerializer(existing_record).data, status=status.HTTP_200_OK)
        else:
            if serializer.is_valid(raise_exception=True):
                try:
                    verification = serializer.save()

                    try:
                        serializer.send_verification_email(request, verification.user_verification_email, verification.user_verification_code)
                    except SMTPConnectError:
                        return Response(
                            {'error': 'Unable to connect to the email server. Please try again later.'},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE
                        )
                    except SMTPException as e:
                        return Response({'error': 'Error sending verification code.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    except requests.exceptions.ConnectionError:
                        return Response({'error': 'Connection error. Please try again.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

                    return Response(EmailVerificationSerializer(verification).data, status=status.HTTP_200_OK)
                except:
                    return Response({'error': str(serializer.errors)}, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmail(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request, verification_code):
        try:
            verification = UserVerification.objects.get(user_verification_code=verification_code)

            if verification.user_verification_expires_at < timezone.now():
                return Response({'detail': 'Verification code has expired.'}, status=status.HTTP_400_BAD_REQUEST)
            verification.user_verification_is_verified = True
            verification.save()

            return HttpResponseRedirect(reverse('user-verified-page'))

        except UserVerification.DoesNotExist:
            return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)
        
class CheckUserVerification(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = CheckUserVerifiedSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            is_verified, user_id = serializer.check_verification_status()
            return Response({'email': serializer.data,'is_verified': is_verified, 'user_account_id': user_id}, status=status.HTTP_200_OK)
        return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
class UserLogin(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def post(self, request):
        data = request.data

        print(data)

        if 'token' in data:
            print('ari?')
            serializer = UserGoogleLoginSerializer(data=data)
        else:
            print('bh ari?')
            serializer = UserLoginSerializer(data=data)

            print('kasulod?')

        if serializer.is_valid(raise_exception=True):
            user = serializer.check_user(data)

            print(user)

            if user.is_staff or user.is_reviewer:
                role = 'Admin' if user.is_staff else 'Reviewer'
                return Response(
                    {'error': f'{role} users are not allowed to access this platform.'},
                    status=status.HTTP_403_FORBIDDEN)
            
            # if SuspendedUser.objects.filter(user_id=user, sus_end__gt=timezone.now()).exists():
            #     return Response(
            #         {'error': 'Your account is currently suspended. Please contact support for further assistance.'},
            #         status=status.HTTP_403_FORBIDDEN
            #     )

            refresh_token = RefreshToken.for_user(user)
            access_token = str(refresh_token.access_token)

            user_role = {
                'is_admin': user.is_staff,
                'is_reviewer': user.is_reviewer,
                'is_assumee': user.is_assumee,
                'is_assumptor': user.is_assumptor
            }
            
            is_approved = False
            try:
                user_app = UserApplication.objects.get(user_id=user)
                print(user_app.user_app_status)
                is_approved = user_app.user_app_status
                print(is_approved)
            except (UserApplication.DoesNotExist):
                return Response({'error': 'User application not found'}, status=status.HTTP_400_BAD_REQUEST)
            except (UserProfile.DoesNotExist):
                return Response({'error': 'User profile not found'}, status=status.HTTP_400_BAD_REQUEST)

            response = {'access': access_token, 'refresh': str(refresh_token), 'user_role': user_role, 'user': {'user_id': user.id, 'email': user.email, 'is_approved': is_approved}}

            login(request, user)
            return Response(response, status=status.HTTP_200_OK)
        print(serializer.errors)
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
    
# class UserGoogleLogin(APIView):
#     def post(self, request):
#         data = request.data
#         serializer = UserGoogleLoginSerializer(data=data)
        
#         if serializer.is_valid(raise_exception=True):
#             user = serializer.check_user(data)
#             token, created = Token.objects.get_or_create(user=user)

#             return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_200_OK)
        
#         return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
    
# class CheckGoogleEmail(APIView):
#     permission_classes = [permissions.AllowAny]
#     def post(self, request):
#         serializer = GoogleSignInCheckSerializer(data=request.data)

#         # print(request.data['token'])

#         if serializer.is_valid(raise_exception=True):
#             exists, data = serializer.check_email()

#             print(exists)

#             if not exists:
#                 return Response({'puta': data['google_id'], 'email': data['email']}, status=status.HTTP_200_OK)
#             else:
#                 return Response({'error': 'Account already exists.'}, status=status.HTTP_400_BAD_REQUEST)
#         else: 
#             print(serializer.errors)
#             return Response({'error': 'Credentials not provided'}, status=status.HTTP_400_BAD_REQUEST)

# class CheckGoogleEmail(APIView):
#     permission_classes = [permissions.AllowAny]
#     def post(self, request):
#         serializer = GoogleSignInCheckSerializer(data=request.data)

#         if serializer.is_valid(raise_exception=True):
#             print(exists)
#             exists, data = serializer.check_email()

#             print(exists)

#             if not exists:
#                 return Response({'credentials': data}, status=status.HTTP_200_OK)
#             else:
#                 return Response({'error': 'Account already exists.'}, status=status.HTTP_400_BAD_REQUEST)

#         return Response({'error': 'Credentials not provided'}, status=status.HTTP_400_BAD_REQUEST)

class UserLogout(APIView):
    def post(self, request):
        try:
            # Attempt to retrieve the refresh token from the request data
            refresh_token = request.data.get('refresh')

            # If a refresh token is provided, blacklist it
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            # Perform the standard logout process
            logout(request)
            return Response(status=status.HTTP_200_OK)

        except Exception as e:
            # Handle errors (e.g., invalid or already blacklisted tokens)
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class GetUserProfile(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user_id=request.user.id)
            prof_serializer = UserProfileSerializer(user_profile)

            return Response({'user_profile': prof_serializer.data}, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UpdateUserProfile(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]        
    def put(self, request):
        try:
            user = UserProfile.objects.get(user_id=request.user.id)
            prof_serializer = UserProfileSerializer(user, data=request.data, partial=True)

            if prof_serializer.is_valid():
                prof_serializer.save()

                return Response({'user_profile': prof_serializer.data}, status=status.HTTP_200_OK)
            return Response(prof_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateUserProfilePicture(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]  

    def put(self, request):
        user_picture = request.data.get('user_prof_pic')

        print(user_picture)

        if not user_picture:
                return Response({'error': 'No picture provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        user_profile = request.user.profile

        folder_name = f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} ({request.user.id})"
        
        try:
            # format, imgstr = img.split(';base64,') 
            ext = 'jpg'
            
            image_data = ContentFile(base64.b64decode(user_picture), name=f"user{request.user.id}_{user_profile.user_prof_fname}_{user_profile.user_prof_lname}.{ext}")

            print(image_data)

            upload_result = cloudinary.uploader.upload(image_data, folder=f"user_images/{folder_name}")

            print(upload_result)

            user_profile.user_prof_pic = upload_result['secure_url'] if image_data else None
            user_profile.save()

            return Response({'message': 'Profile picture updated successfully.', 'url': upload_result['secure_url']},
                            status=status.HTTP_200_OK)
        except Exception as e:
                error_message = str(e)

                if "upload" in error_message.lower():
                    error_message = "An error occurred while uploading the image. Please try again later."

                return JsonResponse({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordLink(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data['email']
            serializer.create_token(email)
            serializer.send_reset_link(email)

            return Response({'message': 'Reset password request sent!'}, status=status.HTTP_200_OK)
    
# class VerifyPasswordResetToken(APIView):
#     permission_classes = [permissions.AllowAny]
#     def get(self, request, user, token):
#             user_id = request.GET.get('key')
#             token = request.GET.get('token')

#             verification = PasswordResetToken.objects.get(user=user)

#             if not verification.reset_token or verification.reset_token_expires_at < timezone.now() or PasswordResetToken.DoesNotExist:
#                 return render('base/forgot_password.html', context={'is_expired': True})
            

#             return redirect('find-password')

class ViewOtherProfile(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, user_id):
        try:
            user = UserModel.objects.get(id=user_id)
            user_profile = UserProfile.objects.get(user_id=user_id)
            user_status = UserApplication.objects.get(user_id=user_id)
            prof_serializer = UserProfileSerializer(user_profile)

            profile_data = prof_serializer.data

            profile_data['application_status'] = user_status.user_app_status
            print(profile_data['application_status'])

            followers = Follow.objects.filter(following_id=user_id).count()
            profile_data['followers'] = followers
            print(followers)

            # Fetch all ratings for this user
            ratings = Rating.objects.filter(to_user_id=user_id).order_by('-created_at')
            average_rating = ratings.aggregate(Avg('rating_value'))['rating_value__avg']
            reviews = RatingSerializerView(ratings, many=True).data if ratings.exists() else []

            print(average_rating)

            print(user.is_active)
            print(reviews)

            listings = []
            if user.is_assumptor:
                listings_query = Listing.objects.filter(user_id=user.id, list_status__in = ['ACTIVE', 'RESERVED', 'SOLD'])
                if listings_query.exists():
                    listing_serializer = ListingSerializer(listings_query, many=True)
                    listings = listing_serializer.data
                    for listing in listings:
                        listing['is_promoted'] = is_promoted(listing['list_id'])

            response_data = {
                'user_profile': profile_data,
                'average_rating': average_rating,
                'isActive': user.is_active,
                'reviews': reviews,
            }

            if user.is_assumptor and listings:
                response_data['listings'] = listings
                
            print('listing yawa')
            print(listings)
            return Response(response_data, status=status.HTTP_200_OK)
        except UserApplication.DoesNotExist:
            return Response({'error': 'User application status not found.'}, status=status.HTTP_404_NOT_FOUND)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(e)
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ChangePasswordAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def put(self, request):
        try:
            user = request.user
            
            currPassword = request.data.get('curr_password')
            newPassword = request.data.get('new_password')

            if not currPassword or not newPassword:
                return Response({'error': 'Current password and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if not user.check_password(currPassword):
                return Response({'error': 'Current password does not match.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if currPassword == newPassword:
                return Response({'error': 'New password cannot be the same as the current password.'}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(newPassword)
            user.save()
            refresh_token = RefreshToken.for_user(user)
            access_token = str(refresh_token.access_token)
            update_last_login(None, user)

            return Response({'access': access_token, 'refresh': str(refresh_token), 'message': 'Password updated successfully!'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetMessageAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, receiver_id):
        # print(receiver_id)
        try:
            user_id = request.user.id

            user1, user2 = (user_id, receiver_id) if user_id > receiver_id else (receiver_id, user_id)
            room = ChatRoom.objects.get(chatroom_user_1=user1, chatroom_user_2=user2)
            room_messages = ChatMessage.objects.filter(chatroom_id=room)\
            .order_by('chatmess_created_at')\
            .values('sender_id', 'chatmess_content', 'chatmess_created_at', 'chatmess_is_read')
                    # serializer = MessageSerializer(room_messages, many=True)

            # print(room_messages)

            return Response({'messages': list(room_messages), 'room_id': f'{room.chatroom_id}'}, status=status.HTTP_200_OK)
        except ChatRoom.DoesNotExist:
            return Response({'detail': 'Chat room not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class MakeOfferAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        user = request.user
        list_id = request.data.get('listing_id')

        try:
            list = Listing.objects.get(list_id=list_id)
        except Listing.DoesNotExist:
            return Response({'error': 'Listing not found.'}, status=status.HTTP_404_NOT_FOUND)

        receiver_id = list.user_id.id
        price = request.data.get('offer_price')
        locale.setlocale(locale.LC_ALL, 'en_PH.UTF-8')
            # double_amnt = double
        formatted_amount = locale.currency(float(price), grouping=True)

        print(formatted_amount)

        existing_offer = Offer.objects.filter(list_id__user_id=receiver_id, user_id=user, offer_status__in=['PENDING', 'ACCEPTED']).first()

        if existing_offer:
            print(existing_offer)
            return Response({
                'error': 'You still have an active offer for this listing.'
            }, status=status.HTTP_400_BAD_REQUEST)


        try:
            Offer.objects.create(offer_price=price, list_id=list, user_id=user)
            
            try:
                receiver = UserModel.objects.get(pk=receiver_id)
            except UserModel.DoesNotExist:
                return Response({'error': 'Recipient not found.'}, status=status.HTTP_404_NOT_FOUND)
            
            chat_content = {'text': f'Made an offer: {formatted_amount}',
                            'file': None,
                            'file_type': None}
            
            chat_room, created = ChatRoom.objects.get_or_create(
                chatroom_user_1=max(user, receiver, key=lambda u: u.id),
                chatroom_user_2=min(user, receiver, key=lambda u: u.id),
                defaults={'chatroom_last_message': chat_content}
            )

            chat_room.chatroom_last_message = chat_content['text']
            chat_room.save()

            chat_message_data = {
                'chatmess_content': chat_content,
                'sender_id': user.id,
                'chatroom_id': chat_room.chatroom_id
            }

            serializer = MessageSerializer(data=chat_message_data)
            if serializer.is_valid():
                serializer.save()
                return Response({'user_id': receiver_id, 'room_id': chat_room.chatroom_id}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)                

        except Exception as e:
            print(str(e))
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CancelOfferAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def put(self, request):
        offer_id = request.data.get('offer_id')
        offer_status = request.data.get('status')

        print(offer_id)
        print(offer_status)

        try:
            offer = Offer.objects.get(offer_id=offer_id)

            if offer.offer_status in ['COMPLETED', 'CANCELLED', 'REJECTED']:
                return Response({'error': f'Cannot cancel an offer with status {offer.offer_status}'}, status=status.HTTP_400_BAD_REQUEST)
            
            offer.offer_status = offer_status
            offer.save()

            return Response({'message': f'Offer {offer_status.lower()}'}, status=status.HTTP_200_OK)

        except Offer.DoesNotExist:
            return Response({'error': 'Offer not found'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(str(e))
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class GetActiveOfferAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, receiver_id):
        receiver_id = receiver_id
        print(request.user.id)
        print(receiver_id)
        try:
            user = request.user

            lastest_active_offer = Offer.objects.filter(user_id=user.id,
                list_id__user_id=receiver_id,
                offer_status__in=['PENDING', 'ACCEPTED', 'PAID']
                ).select_related('list_id__user_id__profile').order_by('-offer_created_at').first()
            
            if not lastest_active_offer:
                return Response({'message': 'No active offers found'}, status=status.HTTP_404_NOT_FOUND)
            
            offer = OfferSerializer(lastest_active_offer).data
            listing = CarListingSerializer(lastest_active_offer.list_id).data

            order_status_map = {
                'ACCEPTED': 'PENDING',
                'PAID': 'PAID'
            }
            if offer['offer_status'] in order_status_map:
                try:
                    order_id = ReservationInvoice.objects.get(
                        order_status=order_status_map[offer['offer_status']],
                        list_id=listing['list_id']
                    )
                    invoice_serializer = ReservationInvoiceSerializer(order_id).data
                    offer['order_id'] = invoice_serializer

                    # if offer['offer_status'] == 'PAID':
                    #     trans = Transaction.objects.get(order_id=order_id.order_id)
                    #     trans_serializer = TransactionSerializer(trans).data
                    #     offer['trans_id'] = trans_serializer

                except ReservationInvoice.DoesNotExist:
                    return Response(
                        {'error': f"No reservation invoice found for status {offer['offer_status']}"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            lister = lastest_active_offer.list_id.user_id.profile
            lister_prof = UserProfileSerializer(lister).data

            print(offer)
            print(lister_prof)
            print(listing)

            return Response({'offer': offer, 'listing': listing, 'lister_profile': lister_prof}, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(str(e))
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AcceptRejectOfferAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def put(self, request):
        try:
            user = request.user
            offer_id = request.data.get('offer_id')
            offer_status = request.data.get('status')
            offer = Offer.objects.get(offer_id=offer_id)

            if offer_status == 'rejected':
                offer.offer_status = 'REJECTED'
            elif offer_status == 'accepted':

                statuses = ['COMPLETED', 'CANCELLED']

                if ReservationInvoice.objects.filter(list_id=offer.list_id).exclude(order_status__in=statuses).exists():
                    return Response({'error': 'There is an existing order for this listing'}, status=status.HTTP_400_BAD_REQUEST)

                offer.offer_status = 'ACCEPTED'
                

                offer.list_id.list_status = 'RESERVED'

                other_offers = Offer.objects.filter(list_id=offer.list_id).exclude(offer_id=offer_id)
                for other_offer in other_offers:
                    other_offer.offer_status = 'REJECTED'
                    other_offer.offer_updated_at = timezone.now().isoformat()
                    other_offer.save()

                    message = f'Offer rejected'

                    messages = {
                        'text': message,
                        'file': None,
                        'file_type': None
                    }

                    chat_room = ChatRoom.objects.get(
                        chatroom_user_1=max(user, other_offer.user_id, key=lambda u: u.id),
                        chatroom_user_2=min(user, other_offer.user_id, key=lambda u: u.id)
                            )

                    ChatMessage.objects.create(
                        sender_id=user, chatmess_content=messages, chatroom_id=chat_room)
                    
                    chat_room.chatroom_last_message = message
                    chat_room.save()

            offer.offer_updated_at = timezone.now().isoformat()
            offer.save()

            message = f'Offer {offer_status}'

            messages = {
                'text': message,
                'file': None,
                'file_type': None
            }
            
            chat_room = ChatRoom.objects.get(
                        chatroom_user_1=max(user, offer.user_id, key=lambda u: u.id),
                        chatroom_user_2=min(user, offer.user_id, key=lambda u: u.id)
                            )

            ChatMessage.objects.create(
                sender_id=user, chatmess_content=messages, chatroom_id=chat_room)
            
            chat_room.chatroom_last_message = message
            chat_room.save()

            return Response({'message': f'Offer {offer_status}'}, status=status.HTTP_200_OK)

        except Offer.DoesNotExist:
                return Response({'error': 'Offer not not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({'error': f'An error occured: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# def save_message(self, user_id, message, receiver_id):
#         if int(user_id) > int(receiver_id):
#             user1 = UserModel.objects.get(id=user_id)
#             user2 = UserModel.objects.get(id=receiver_id)
#         else:
#             user2 = UserModel.objects.get(id=user_id)
#             user1 = UserModel.objects.get(id=receiver_id)

#         room_id = ChatRoom.objects.get(Q(chatroom_user_1=user1, chatroom_user_2=user2))
#         user = UserModel.objects.get(id=int(user_id))

#         ChatMessage.objects.create(
#             sender_id=user, chatmess_content=message, chatroom_id=room_id)
        
#         return room_id.chatroom_id

class AssumptorListOffers(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        try:
            assumptor = request.user

            offers = Offer.objects.filter(list_id__user_id=assumptor, offer_status='PENDING')

            serialized_offers = OfferSerializer(offers, many=True).data

            print('serialized_offers')
            # print(serialized_offers)

            try:

                for offer in serialized_offers:
                    listing = Listing.objects.get(list_id=offer['list_id'])
                    listing_deets = CarListingSerializer(listing).data
                    offer['list_image'] = listing_deets['list_content']['images'][0]
                    offer['reservation'] = listing_deets['list_content']['reservation']

                    print(listing_deets['list_content'])

                    user = UserProfile.objects.get(user_id=offer['user_id'])
                    user_prof = UserProfileSerializer(user).data
                    offer['user_fullname'] = user_prof['user_prof_fname'] + ' ' + user_prof['user_prof_lname']

                    chat_room = ChatRoom.objects.get(
                    chatroom_user_1=max(user.user_id, assumptor, key=lambda u: u.id),
                    chatroom_user_2=min(user.user_id, assumptor, key=lambda u: u.id)
                        )
                    
                    offer['chatroom_id'] = chat_room.chatroom_id
            except Offer.DoesNotExist or Listing.DoesNotExist or UserProfile.DoesNotExist or ChatRoom.DoesNotExist or UserModel.DoesNotExist:
                return Response({'error': 'Resquest invalid'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            print(serialized_offers)
            return Response({'offers': serialized_offers}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': f'Unexpected error occured: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CreateOrder(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        try:
            user = request.user
            offer_id = request.data.get('offer_id')
            amount = request.data.get('amount')
            user_id = request.data.get('user_id')
            offer = Offer.objects.get(offer_id=offer_id)
            # amount = offer.offer_price
            list_id = offer.list_id

            statuses = ['COMPLETED', 'CANCELLED']

            if ReservationInvoice.objects.filter(list_id=list_id).exclude(order_status__in=statuses).exists():
                return Response({'error': 'There is an existing order for this listing'}, status=status.HTTP_400_BAD_REQUEST)

            inv = ReservationInvoice.objects.create(order_price=amount, offer_id=offer, list_id=list_id, user_id=offer.user_id)
            inv_serializer = ReservationInvoiceSerializer(inv)

            return Response({'message': 'Offer accepted', 'order': inv_serializer.data}, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(e)
            return Response({'error': f'Error creating order: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CancelOrder(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, order_id):
        try:
            user = request.user
            order = ReservationInvoice.objects.get(order_id=order_id)

            if user != order.user_id and user != order.list_id.user_id:
                    return Response({'error': 'You are not authorized to cancel this order'}, status=status.HTTP_403_FORBIDDEN)

            if order.order_status == 'CANCELLED':
                    return Response({'error': 'Order is already canceled'}, status=status.HTTP_400_BAD_REQUEST)

            order.order_status = 'CANCELLED'
            order.save()

            if order.offer_id:
                order.offer_id.offer_status = 'CANCELLED'
                order.offer_id.save()

            order.list_id.list_status = 'ACTIVE'
            order.list_id.save()

            return Response({'message': 'Order cancelled'}, status=status.HTTP_200_OK)
        except ReservationInvoice.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(str(e))
            return Response({'error': 'An error occurred while canceling the order'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetOrder(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, order_id):
        user = request.user
        print(user)
        try:
            order = ReservationInvoice.objects.get(order_id=order_id, user_id=user)
            order_serializer = ReservationInvoiceSerializer(order).data

            print(order)
            list_id = str(order.list_id)
            listing = Listing.objects.get(list_id=list_id)
            list_serializer = ListingSerializer(listing).data
            print(listing)
            listing_owner = UserProfile.objects.get(user_id=listing.user_id)
            prof_serializer = UserProfileSerializer(listing_owner).data

            if order.offer_id:
                order_serializer['offer_price'] = order.offer_id.offer_price

            if order.order_status == 'PAID':
                trans = Transaction.objects.get(order_id=order.order_id)
                order_serializer['order_paid_on'] = trans.transaction_date

            print(order_serializer)

            return Response({'order': order_serializer, 'list': list_serializer, 'lister': prof_serializer}, status=status.HTTP_200_OK)
        except ReservationInvoice.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)


class GetListingOfferAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, receiver_id):
        try:
            user = request.user

            lastest_active_offer = Offer.objects.filter(user_id=receiver_id,
                list_id__user_id=user.id,
                offer_status__in=['PENDING', 'ACCEPTED', 'PAID']
                ).select_related('list_id__user_id__profile').order_by('-offer_created_at').first()
            
            if not lastest_active_offer:
                return Response({'message': 'No active offers found'}, status=status.HTTP_404_NOT_FOUND)
            
            offer = OfferSerializer(lastest_active_offer).data
            listing = CarListingSerializer(lastest_active_offer.list_id).data
            
            order_status = {
                'ACCEPTED': 'PENDING',
                'PAID': 'PAID'
            }

            if offer['offer_status'] in order_status:
                try:
                    order_id = ReservationInvoice.objects.get(
                        order_status=order_status[offer['offer_status']],
                        list_id=listing['list_id']
                    )
                    invoice_serializer = ReservationInvoiceSerializer(order_id).data
                    offer['order_id'] = invoice_serializer
                except ReservationInvoice.DoesNotExist:
                    return Response(
                        {'error': f"No reservation invoice found for status {offer['offer_status']}"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            lister = lastest_active_offer.list_id.user_id.profile
            lister_prof = UserProfileSerializer(lister).data

            # print(offer)
            # print(lister_prof)
            # print(listing)
            # print(offer['order_id'])


            return Response({'offer': offer, 'listing': listing, 'lister_profile': lister_prof}, status=status.HTTP_200_OK)
                
            
        except Exception as e:
            print(str(e))
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserChatRoomAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def get(self, request):
        try:
            user_id = request.user.id

            rooms = ChatRoom.objects.filter(Q(chatroom_user_1=user_id) | Q(chatroom_user_2=user_id)).values('chatroom_id', 'chatroom_last_message')
            chatmates = ChatRoom.objects.filter(
                Q(chatroom_user_1=user_id) | Q(chatroom_user_2=user_id)
            ).annotate(
                chatmate=Case(
                    When(chatroom_user_1=user_id, then=F('chatroom_user_2')),
                    When(chatroom_user_2=user_id, then=F('chatroom_user_1'))
                ),
                last_message_date=Max('messages__chatmess_created_at'),
                last_sender_id=Subquery(
                    ChatMessage.objects.filter(
                        chatroom_id=OuterRef('chatroom_id')
                    ).order_by('-chatmess_created_at').values('sender_id')[:1]),
                isRead=Subquery(
                    ChatMessage.objects.filter(
                        chatroom_id=OuterRef('chatroom_id')
                    ).order_by('-chatmess_created_at').values('chatmess_is_read')[:1]),
            ).values('chatmate', 'chatroom_id', 'chatroom_last_message', 'last_message_date', 'last_sender_id', 'isRead')
                        
            chatmates_info = UserModel.objects.filter(id__in=chatmates.values('chatmate')).values(
                'id',
                'profile__user_prof_fname',
                'profile__user_prof_lname',
                'profile__user_prof_pic'
            )
            
            inbox = []
            for room in chatmates:
                chatmate_profile = next((info for info in chatmates_info if info['id'] == room['chatmate']), None)
                
                inbox.append({
                    'chatroom_id': room['chatroom_id'],
                    'chatmate_id': room['chatmate'],
                    'chatmate_name': f"{chatmate_profile['profile__user_prof_fname']} {chatmate_profile['profile__user_prof_lname']}" if chatmate_profile else None,
                    'chatmate_pic':chatmate_profile['profile__user_prof_pic'],
                    'last_message': room['chatroom_last_message'],
                    'last_message_date': room['last_message_date'],
                    'sender_id': room['last_sender_id'],
                    'mess_isread': room['isRead']
                })
            
            inbox = sorted(inbox, key=lambda x: x['last_message_date'], reverse=True)

            print(chatmates)
            print(user_id)
            print(inbox)

            return Response({'rooms': inbox, }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class CarListingCreate(generics.CreateAPIView):
    queryset = Listing.objects.all()
    serializer_class = CarListingSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # Validate the data
        list_instance = self.perform_create(serializer)

        ListingApplication.objects.create(list_id=list_instance)

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    def perform_create(self, serializer):
        instance = serializer.save(user_id=self.request.user)
        
        return instance

class AddCoinsToWalletView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = WalletSerializer

    def get_object(self):
        user = self.request.user
        wallet = Wallet.objects.filter(user_id=user.id).first()
        
        if not wallet:
            raise Http404("Wallet not found for the user.")
        
        return wallet

    def perform_update(self, serializer):
        instance = self.get_object()  # Get the wallet instance
        coins_to_add = self.request.data.get('coins_to_add', 0)

        coins_to_add = Decimal(coins_to_add)

        instance.wall_amnt += coins_to_add
        instance.save()

        return Response({'new_balance': instance.wall_amnt}, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name='dispatch')
class GetTotalCoinsView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 
    queryset = Wallet.objects.all()
    serializer_class = WalletSerializer

    def get_object(self):
        user = self.request.user
        try:
            # Try to retrieve the wallet for the logged-in user
            wallet = Wallet.objects.get(user_id=user.id)
        except Wallet.DoesNotExist:
            # If wallet doesn't exist, create a new one with default values
            wallet = Wallet.objects.create(user_id=user.id, wall_amnt=0)
            wallet.save()
        
        return wallet

    def get(self, request, *args, **kwargs):
        # Get the wallet and serialize the data
        wallet = self.get_object()
        serializer = self.get_serializer(wallet)
        return Response(serializer.data)
class ListingStatus(APIView):
    """
    API view to retrieve the status of a listing.
    """
    def get(self, request, listing_id):
        try:
            listing = Listing.objects.get(pk=listing_id)
            return Response({'list_status': listing.list_status}, status=status.HTTP_200_OK)
        except Listing.DoesNotExist:
            return Response({'error': 'Listing not found'}, status=status.HTTP_404_NOT_FOUND)
class UpdateListingAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def put(self, request, listing_id):
        try:
            # Retrieve the listing
            listing = Listing.objects.get(list_id=listing_id)
        except Listing.DoesNotExist:
            return Response({'error': 'Listing not found'}, status=status.HTTP_404_NOT_FOUND)

        # Get the existing list_content
        current_content = listing.list_content or {}
        print('Updated nani')
        print(request.data)  # Print the entire request data to check structure

        # Ensure 'list_content' exists in request data
        updated_content = request.data.get('list_content', {})

        # Merge current content with incoming updates
        updated_content = {**current_content, **updated_content}
        
        print('Updated content after merge:')
        print(updated_content)

        # Save the updated listing
        listing.list_content = updated_content
        listing.list_status == 'PENDING'
        listing.save()
        # Now, update the corresponding ListingApplication
        try:
            listing_application = ListingApplication.objects.get(list_id=listing)
            listing_application.list_app_status = 'PENDING'  # Update the list_app_status to 'PENDING'
            listing_application.save()
        except ListingApplication.DoesNotExist:
            return Response({'error': 'Listing application not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'message': 'Listing updated successfully', 'updated_content': updated_content}, status=status.HTTP_200_OK)

class PromotedListingsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        try:
            promoted_listings = PromoteListing.objects.all().order_by('?')
            serializer = PromoteListingDetailSerializer(promoted_listings, many=True)

            for listing in serializer.data:
                listing['list_id']['is_promoted'] = True
            print('serializer.data prom')
            print(serializer.data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class ListingView(APIView):
    def get(self, request):
        listings = Listing.objects.filter(list_status='ACTIVE')
        response_data = []

        # Get the current time, ensuring it's timezone-aware
        now = timezone.now()

        for listing in listings:
            # Retrieve the latest promotion for the listing
            promotion = PromoteListing.objects.filter(list_id=listing).order_by('-prom_end').first()

            # Check if the promotion exists and is still active
            if promotion:
                prom_end = promotion.prom_end
                if timezone.is_naive(prom_end):
                    prom_end = timezone.make_aware(prom_end)  # Make it timezone-aware
                
                # Check if the promotion has expired
                if prom_end < now:
                    # Check if list_duration is still valid
                    list_duration = listing.list_duration
                    if list_duration and now > list_duration:
                        # If both the promotion has expired and the listing is expired, archive the listing
                        listing.list_status = 'ARCHIVED'
                        listing.save()

                    # Delete the expired promotion from the PromoteListing table
                    promotion.delete()

                    promotion_data = None  # Since the promotion has expired
                else:
                    promotion_data = {
                        'prom_end': prom_end.isoformat()  # Convert to ISO format for the response
                    }
            else:
                # If no promotion, mark as archived if the listing is expired
                list_duration = listing.list_duration
                if list_duration and now > list_duration:
                    listing.list_status = 'ARCHIVED'
                    listing.save()
                promotion_data = None  # No promotion available

            response_data.append({
                'list_id': str(listing.list_id),
                'list_status': listing.list_status,
                'list_duration': listing.list_duration.isoformat() if listing.list_duration else None,
                'promotion': promotion_data
            })

        return Response(response_data, status=status.HTTP_200_OK)

class PromoteListingView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = PromoteListingSerializer

    def perform_create(self, serializer):
        # Get the list_id from validated data
        list_id = serializer.validated_data.get('list_id')
        if not list_id:
            raise ValidationError("list_id is required.")
        
        # Get the duration from the request data
        duration = self.request.data.get('duration', 30)  # Default to 30 days if not provided
        try:
            duration = int(duration)
        except ValueError:
            raise ValidationError("Invalid duration value.")

        # Save the promotion with start and calculated end dates based on duration
        promote_listing = serializer.save(
            prom_start=timezone.now(),
            prom_end=timezone.now() + timezone.timedelta(days=duration),  # Use dynamic duration
            list_id=list_id
        )

        # Get the amount from the request body
        amount = self.request.data.get("amount", 0)
        amount = Decimal(amount)

        # Create a transaction for the promotion action
        transaction = Transaction.objects.create(
            user_id=self.request.user,
            transaction_amount=amount,  # Use the amount passed from the request
            transaction_type='PROMOTE',
            transaction_date=timezone.now(),
        )
        
        return Response({
            "message": "Listing promoted successfully.",
            "transaction_id": transaction.transaction_id,
        }, status=status.HTTP_201_CREATED)


        
class DeductCoinsView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = WalletSerializer

    def get_object(self):
        return Wallet.objects.get(user_id=self.request.user)

    def update(self, request, *args, **kwargs):
        wallet = self.get_object()
        amount_to_deduct = request.data.get("amount", 0)
        amount_to_deduct = Decimal(amount_to_deduct)

        # Check if the list_id is provided in the request
        list_id = request.data.get("list_id")
        if not list_id:
            return Response({'error': 'list_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the listing is already promoted
        if PromoteListing.objects.filter(list_id=list_id).exists():
            return Response({'Listing is already promoted.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check for sufficient coins
        if wallet.wall_amnt < amount_to_deduct:
            return Response({'error': 'Insufficient coins'}, status=status.HTTP_400_BAD_REQUEST)

        # Deduct coins and save wallet
        wallet.wall_amnt -= amount_to_deduct
        wallet.save()
        return Response({'new_balance': wallet.wall_amnt})

class DeleteListingView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = CarListingSerializer

    def update(self, request, *args, **kwargs):
        listing_id = kwargs.get("listing_id")
        
        # Check if the listing exists in PromoteListing and delete it if found
        try:
            promote_listing = PromoteListing.objects.get(list_id=listing_id)
            promote_listing.delete()
        except PromoteListing.DoesNotExist:
            pass  # No action needed if listing is not promoted

        # Check if the listing exists in the Listing table
        try:
            listing = Listing.objects.get(list_id=listing_id)

            # Check if the listing is already archived
            if listing.list_status == "ARCHIVED":
                return Response({"message": "Listing is already archived"}, status=status.HTTP_200_OK)
                

            # Set status to 'ARCHIVED' and save
            listing.list_status = "ARCHIVED"
            listing.save()
            return Response({"message": "Listing archived successfully"}, status=status.HTTP_200_OK)

        except Listing.DoesNotExist:
            raise Exception({"error": "Listing not found"})

class FilteredUserListings(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, list_status):
        status_filter = list_status

        try:
            # Filter listings associated with the user
            user_listings = Listing.objects.filter(user_id=request.user.id)
            
            # Apply the status filter if provided
            if status_filter:
                # First, filter by the status of ListingApplication
                user_listings = user_listings.filter(
                    listingapplication__list_app_status=status_filter
                )
                
                # Now, filter by the list_status of the Listing table, 
                # if the status is 'APPROVED' and list_status is 'active'
                if status_filter == 'APPROVED':
                    user_listings = user_listings.filter(list_status='PENDING')

            # Serialize the listings data
            serializer = CarListingSerializer(user_listings, many=True)

            for listing in serializer.data:
                print('is_promoted?')
                print(is_promoted(listing['list_id']))
                listing['is_promoted'] = is_promoted(listing['list_id'])

            return Response({'listings': serializer.data}, status=status.HTTP_200_OK)

        except Listing.DoesNotExist:
            print("No listings found for this user.")  # Debugging: log if no listings found
            return Response({'error': 'No listings found for this user.'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            print("Exception occurred:", str(e))  # Debugging: log the exception
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UpdateListingStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def patch(self, request, listing_id):
        try:
            # Fetch the listing by ID
            listing = Listing.objects.get(list_id=listing_id)

            # Get the amount from the request body
            amount = request.data.get("amount", 0)
            amount = Decimal(amount)

            # Update the list_status to 'active'
            listing.list_status = 'ACTIVE'            
            listing.list_duration = timezone.now() + timedelta(days=30)
            listing.save()

            # Create a transaction for the listing status update
            transaction = Transaction.objects.create(
                user_id=request.user,
                transaction_amount=amount,  # Use the amount passed from the request
                # transaction_status='COMPLETED',
                transaction_date=timezone.now(),
                transaction_type='ADD LISTING'
            )

            # Return a success response
            return Response({
                "message": "Listing status updated successfully.",
                "transaction_id": transaction.transaction_id
            }, status=200)
        except Listing.DoesNotExist:
            # If the listing doesn't exist, return a 404 response
            raise Exception(detail="Listing not found.")


class ListingByCategoryView(APIView):
    serializer_class = ListingSerializer
    permission_classes = [permissions.AllowAny]  # Adjust if needed for authenticated users only

    def get(self, request, category, *args, **kwargs):
        # Fetch listings for the category and ensure they are active
        all_listings = Listing.objects.filter(list_content__category=category, list_status='ACTIVE', user_id__is_active=True)

        # Separate listings by the logged-in user (if authenticated)
        user = request.user.id if request.user.is_authenticated else None

        if user:
            user_listings = all_listings.filter(user_id=user)  # Listings of the logged-in user
            other_listings = all_listings.exclude(user_id=user)  # Listings of other users
            # Combine user listings first, followed by others
            combined_listings = list(user_listings) + list(other_listings)
        else:
            # If the user is not authenticated, return all listings as is
            combined_listings = list(all_listings)

        promote_listings = PromoteListing.objects.filter(
            list_id__in=[listing.list_id for listing in combined_listings]
        )

        serializer = self.serializer_class(combined_listings, many=True)

        for listing in serializer.data:
            print('is_promoted?')
            print(is_promoted(listing['list_id']))
            listing['is_promoted'] = is_promoted(listing['list_id'])

        print('serializer.data real ' + category)
        print(serializer.data)
        return Response(serializer.data)

def is_promoted(list_id):
    try:
        promote = PromoteListing.objects.get(list_id=list_id)
        return promote.prom_end >= timezone.now()
    except PromoteListing.DoesNotExist:
        return False

@method_decorator(csrf_exempt, name='dispatch')
class ListingDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, list_id, *args, **kwargs):
        # Get the listing by list_id
        listing = get_object_or_404(Listing, list_id=list_id)

        # First, check if there's an approved listing application
        listing_application = ListingApplication.objects.filter(list_id=listing).first()

        statuses = ['ACTIVE', 'RESERVED']

        # If no approved listing application, set has_active_listing to False
        if not listing_application:
            has_active_listing = False
            list_app_status = None  # No approved application
        else:
            # If there's an approved listing application, check the Listing table for 'active' status
            existing_active_listing = Listing.objects.filter(
                user_id=listing.user_id,  # assuming user_id is the user who owns the listing
                list_status__in=statuses
            ).first()

            if existing_active_listing:
                # If there's an active listing, set has_active_listing to True
                has_active_listing = True
                list_app_status = listing_application.list_app_status  # Already 'APPROVED'
            else:
                # If no active listing, set has_active_listing to False
                has_active_listing = False
                list_app_status = listing_application.list_app_status  # 'APPROVED'

        # Serialize the listing data
        serializer = CarListingSerializer(listing)

        # Extract the data (ensure it's a dict, not a list)
        data = serializer.data if isinstance(serializer.data, dict) else serializer.data[0]
        data['list_app_status'] = list_app_status
        data['has_active_listing'] = has_active_listing

        print("Modified Response Data: ", data)

        return Response(data)
    
#joselito update    
class ListingRejectedDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, list_id, *args, **kwargs):
        # Get the listing by list_id
        listing = get_object_or_404(Listing, list_id=list_id)

        # First, check if there's a rejected listing application
        listing_application = ListingApplication.objects.filter(list_id=listing, list_app_status='REJECTED').first()

        # If no rejected listing application, set has_active_listing to False
        if not listing_application:
            has_active_listing = False
            list_app_status = None  # No rejected application
            list_reason = None  # No reason available
        else:
            # If there's a rejected listing application, check the Listing table for 'active' status
            existing_active_listing = Listing.objects.filter(
                user_id=listing.user_id,  # assuming user_id is the user who owns the listing
                list_status='ACTIVE'
            ).first()

            if existing_active_listing:
                # If there's an active listing, set has_active_listing to True
                has_active_listing = True
                list_app_status = listing_application.list_app_status  # Already 'REJECTED'
            else:
                # If no active listing, set has_active_listing to False
                has_active_listing = False
                list_app_status = listing_application.list_app_status  # 'REJECTED'

            # Get the rejection reason from the listing application
            list_reason = listing_application.list_reason

        # Serialize the listing data
        serializer = CarListingSerializer(listing)

        # Extract the data (ensure it's a dict, not a list)
        data = serializer.data if isinstance(serializer.data, dict) else serializer.data[0]
        data['list_app_status'] = list_app_status
        data['has_active_listing'] = has_active_listing
        data['list_reason'] = list_reason  # Add the rejection reason to the response

        print("Modified Response Data: ", data)

        return Response(data)
    
class AssumptorListings(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def get(self, request, list_status):
        user = request.user.id


        listings = Listing.objects.filter(user_id=user, list_status=list_status)

        print('listings')
        print(f"Listings count: {listings.count()}")
        print(listings.query)

        serializer = ListingSerializer(listings, many=True)

        for listing in serializer.data:
            listing['is_promoted'] = is_promoted(listing['list_id'])
        print(serializer.data)
        
        return Response({'listings': serializer.data}, status=status.HTTP_200_OK)
    
class AssumptorViewListings(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def get(self, request, user_id):
        user = UserModel.objects.get(id=user_id)

        listings = Listing.objects.filter(user_id=user, list_status__in = ['ACTIVE', 'RESERVED', 'SOLD'])

        if listings.exists():
            serializer = ListingSerializer(listings, many=True)

            for listing in serializer.data:
                listing['is_promoted'] = is_promoted(listing['list_id'])
            
            return Response({'listings': serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'No listing available'}, status=status.HTTP_204_NO_CONTENT)

class RandomListingListView(APIView): 
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user_id = request.user.id  # Get the authenticated user's ID

        # Count listings and determine how many to return
        total_listings = Listing.objects.exclude(user_id=user_id).filter(list_status='ACTIVE').aggregate(count=Count('user_id'))['count']
        listings_to_return = 10 if total_listings >= 10 else total_listings
        
        # Fetch all listings excluding the user's own listings and with list_status='ACTIVE'
        all_listings = list(Listing.objects.exclude(user_id=user_id).filter(list_status='ACTIVE'))
        
        # Ensure there are listings to sample from
        if not all_listings:
            return Response([], status=status.HTTP_200_OK)  # Return an empty list if no listings available

        # Randomly sample listings
        random_listings = random.sample(all_listings, min(listings_to_return, len(all_listings)))

        # Serialize and return the random listings
        serializer = ListingSerializer(random_listings, many=True)

        for listing in serializer.data:
            listing['is_promoted'] = is_promoted(listing['list_id'])

        return Response(serializer.data, status=status.HTTP_200_OK)
    
class FavoritesView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def get(self, request):
        user = request.user
        favorites = Favorite.objects.filter(user_id=user).order_by('-fav_date')
        
        # Serialize the favorites, which includes the nested listings
        serializer = FavoriteSerializer(favorites, many=True)

        # Log the serialized data to verify its structure
        print('Favorites Data:', serializer.data)  # Log the serialized data
        #print(f"Listing Content for Favorite ID {favorites.fav_id}: {favorites.list_content}")
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class FavoritesMarkView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def get(self, request):
        user = request.user
        favorites = Favorite.objects.filter(user_id=user)
        
        # Serialize the favorites, which includes the nested listings
        serializer = FavoriteMarkSerializer(favorites, many=True)

        # Log the serialized data to verify its structure
        print('Favorites Data:', serializer.data)  # Log the serialized data
        #print(f"Listing Content for Favorite ID {favorites.fav_id}: {favorites.list_content}")
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class AddFavoriteView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def post(self, request):
        user = request.user
        listing_id = request.data.get('listing_id')

        # Log the received listing ID
        print(f"Received listing_id: {listing_id} from user: {user.id}")

        # Fetch the listing object using the correct field name
        listing = get_object_or_404(Listing, pk=listing_id)

        # Check if the favorite already exists
        favorite, created = Favorite.objects.get_or_create(list_id=listing, user_id=user)

        if created:
            print(f"Added favorite for user {user.id} on listing {listing_id} at {timezone.now()}")
            return Response({'message': 'Added to favorites'}, status=status.HTTP_201_CREATED)
        else:
            print(f"Favorite already exists for user {user.id} on listing {listing_id}")
            return Response({'message': 'Already in favorites'}, status=status.HTTP_400_BAD_REQUEST)

class RemoveFavoriteView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def delete(self, request):
        user = request.user
        list_id = request.data.get('list_id')  # Get the fav_id from the request

        try:
            favorite = Favorite.objects.get(list_id=list_id, user_id=user)  # Use fav_id to find the favorite
            favorite.delete()
            return Response({'message': 'Removed from favorites'}, status=status.HTTP_200_OK)
        except Favorite.DoesNotExist:
            return Response({'error': 'Favorite not found'}, status=status.HTTP_404_NOT_FOUND)
        
class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def get(self, request, user_id):
        try:
            # Fetch the user profile based on the provided user_id
            user_profile = UserProfile.objects.get(user_id=user_id)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the user profile data
        serializer = UserProfileSerializer(user_profile)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class DeactivateUserAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 
    
    def get(self, request):
        user = request.user

        try:
            user.is_active = False
            user.save()

            return Response({"success": "User deactivated successfully."}, status=status.HTTP_200_OK)
        
        except UserModel.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

@method_decorator(csrf_exempt, name='dispatch')
class ListingSearchView(APIView):
    """
    View to search listings or return all listings when no search query is provided.
    """
    serializer_class = CarListingSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        query = self.request.query_params.get('query', None)
        category = self.request.query_params.get('category', None)
        logger.debug(f'Received search query: {query}, category: {category}')

        listings = Listing.objects.filter(list_status="ACTIVE")  

        if category:
            listings = listings.filter(category__name=category)

        if query:
            listings = listings.filter(title__icontains=query)

        logger.debug(f'Listings found: {listings.count()}')

        if not listings.exists():
            logger.warning('No listings found')
            return Response({'message': 'No listings found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(listings, many=True)

        for listing in serializer.data:
            print('is_promoted?')
            print(is_promoted(listing['list_id']))
            listing['is_promoted'] = is_promoted(listing['list_id'])

        logger.debug(f'Serialized data: {serializer.data}')
        return Response(serializer.data, status=status.HTTP_200_OK)

###### render views ######

def email_verified(request):
    return render(request, 'base/email-verified.html')

class CheckGoogleEmail(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get('token')

        # print(token)

        if not token:
            return JsonResponse({'error': 'No token provided'}, status=400)

        try:
            clientId = os.getenv('OAUTH_CLIENT_ID')

            print(clientId)
            
            id_info = token_auth.verify_oauth2_token(token, requests.Request(), clientId)

            print(id_info)

            google_id = id_info['sub'] 
            email = id_info['email']

            user = UserModel.objects.filter(google_id=google_id).first() or UserModel.objects.filter(email=email).first()

            if user:
                return Response({'error': 'Account already exists.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return JsonResponse({'status': 'success', 'google_id': google_id, 'email': email}, status=status.HTTP_200_OK)
        except ValueError as e:
            print(e)
            return JsonResponse({'error': f'Invalid token: {e}'}, status=status.HTTP_400_BAD_REQUEST)


class FollowUser(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = FollowSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        # Extract assumptor_user from the incoming data
        data['following_id'] = data.get('user_id')  # Ensure you set the correct field name
        data['follower_id'] = request.user.id  # Get the current user's ID

        # Debugging: Log the data being sent to the serializer
        print("Incoming data for serializer:", data)

        # Create the serializer instance with the corrected data
        serializer = self.serializer_class(data=data)

        # Validate and save the serializer data
        if serializer.is_valid():
            serializer.save()
            following = serializer.data
            print(following)
            try:
                id = following['following_id']
                user = UserModel.objects.get(id=id)
            except UserModel.DoesNotExist:
                return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
                
            try:
                prof = UserProfile.objects.get(user_id=user)
            except UserProfile.DoesNotExist:
                return Response({'error': 'User profile does not exist'}, status=status.HTTP_404_NOT_FOUND)

            # Prepare the follower data for response
            following_data = {
                'user_id': prof.user_id.id, 
                'fullname': prof.user_prof_fname + ' ' + prof.user_prof_lname,
                'profile': prof.user_prof_pic
            }
            print(following_data)
            return Response(following_data, status=status.HTTP_200_OK)
        # Log serializer errors for debugging
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UnfollowUser(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    queryset = Follow.objects.all()

    def delete(self, request, *args, **kwargs):
        print("Received DELETE request")  # Debugging line
        print("User:", request.user)  # Print the authenticated user
        print("Request data:", request.data)  # Print the request data
        
        user_id = request.data.get('user_id')
        print("User ID to unfollow:", user_id)  # Print the user ID to unfollow

        if user_id is None:
            print("No user_id provided in the request.")  # Debugging line
            return Response({"detail": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            following = self.queryset.get(follower_id=request.user, following_id=user_id)
            following.delete()
            print(f"Successfully unfollowed user ID {user_id}")  # Debugging line
            return Response({"detail": "Unfollowed successfully."}, status=status.HTTP_200_OK)
        except Follow.DoesNotExist:
            print(f"Following relationship does not exist for user ID {user_id}")  # Debugging line
            return Response({"detail": "Following relationship does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print("An error occurred:", str(e))  # Debugging line for any other exceptions
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class ListFollowing(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        followings = Follow.objects.filter(follower_id=request.user)
        serializer = FollowSerializer(followings, many=True)
        print(serializer.data)
        following = serializer.data
        following_list = []
        for follow in following:
            try:
                id = follow['following_id']
                user = UserModel.objects.get(id=id)
            except UserModel.DoesNotExist:
                return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
                
            try:
                prof = UserProfile.objects.get(user_id=user)
            except UserProfile.DoesNotExist:
                return Response({'error': 'User profile does not exist'}, status=status.HTTP_404_NOT_FOUND)

            # Prepare the follower data for response
            following_data = {
                'user_id': prof.user_id.id, 
                'fullname': prof.user_prof_fname + ' ' + prof.user_prof_lname,
                'profile': prof.user_prof_pic
            }

            following_list.append(following_data)
        print(following_list)
        return Response({'following': following_list}, status=status.HTTP_200_OK)


class ListFollower(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        followers = Follow.objects.filter(following_id=request.user)
        serializer = FollowSerializer(followers, many=True)
        # print(serializer.data)
        follower = serializer.data
        follower_list = []
        for follow in follower:
            try:
                id = follow['follower_id']
                user = UserModel.objects.get(id=id)
            except UserModel.DoesNotExist:
                return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
                
            try:
                prof = UserProfile.objects.get(user_id=user)
            except UserProfile.DoesNotExist:
                return Response({'error': 'User profile does not exist'}, status=status.HTTP_404_NOT_FOUND)

            follower_data = {
                'user_id': prof.user_id.id,  
                'fullname': prof.user_prof_fname + ' ' + prof.user_prof_lname,
                'profile': prof.user_prof_pic  
            }

            follower_list.append(follower_data)
            
        print(follower_list)
        return Response({'follower': follower_list}, status=status.HTTP_200_OK)
    

class TransactionHistoryView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    def get(self, request):
        # Fetch all transactions for the authenticated user
        user = request.user
        transactions = Transaction.objects.filter(user_id=user)  # Assuming user_id is the user who made the transaction

        # Serialize the data
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data)

class CreatePaypalOrder(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        url = "https://api.sandbox.paypal.com/v2/checkout/orders"
        client_id = clientId
        secret_key = secretKey
        credentials = f"{client_id}:{secret_key}"
        auth_header = {
            "Authorization": f"Basic {base64.b64encode(credentials.encode()).decode()}",
            "Content-Type": "application/json"
        }

        amount = request.data.get('amount', '10.00')

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
            return Response({
                'id': order_data['id'],
                'approval_url': next(link['href'] for link in order_data['links'] if link['rel'] == 'approve')
            })
        except req.exceptions.RequestException as e:
            logger.error(f"PayPal API error: {str(e)}")
            return Response({'error': 'Unable to create PayPal order'}, status=500)
        
class CapturePaypalOrder(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        order_id = request.data.get('orderID')
        amount = request.data.get('amount')

        if not order_id:
            return Response({'error': 'Missing orderID'}, status=400)

        client_id = clientId
        secret_key = secretKey
        credentials = f"{client_id}:{secret_key}"
        auth_header = {
            "Authorization": f"Basic {base64.b64encode(credentials.encode()).decode()}",
            "Content-Type": "application/json"
        }

        capture_url = f"https://api.sandbox.paypal.com/v2/checkout/orders/{order_id}/capture"

        try:
            capture_response = req.post(capture_url, headers=auth_header)
            capture_response.raise_for_status()
            
            capture_data = capture_response.json()
            
            # Extract capture details from the response
            capture_id = capture_data['purchase_units'][0]['payments']['captures'][0]['id']
            capture_amount = capture_data['purchase_units'][0]['payments']['captures'][0]['amount']['value']
             # Retrieve the UserAccount instance associated with the currently authenticated user
            user_account = request.user

            # Create a new transaction and link it to the logged-in user
            transaction = Transaction.objects.create(
                transaction_paypal_order_id=order_id,
                transaction_paypal_capture_id=capture_id,
                transaction_amount=capture_amount,
                transaction_date=timezone.now(),  # Set the current timestamp
                user_id=user_account  # Link the UserAccount instance directly
            )

            return Response({
                'status': 'COMPLETED',
                'order_id': order_id,
                'capture_id': capture_id,
                'amount': capture_amount,
                'transaction_id': transaction.transaction_id  # Return the transaction ID for reference
            })
        except req.exceptions.RequestException as e:
            logger.error(f"PayPal capture error: {str(e)}")
            return Response({'error': 'Payment capture failed'}, status=500)
        
class PaypalPaymentCancelled(APIView):
        def get(self, request, *args, **kwargs):
                # You can handle cancellation logic here, such as notifying the user
                return JsonResponse({'status': 'Payment cancelled'})
        
@method_decorator(csrf_exempt, name='dispatch')
class RefundPayment(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request, *args, **kwargs):
        try:
            # Query the first transaction in the database
            transaction = Transaction.objects.last()

            if not transaction:
                return JsonResponse({"error": "No transaction found"}, status=404)

            # Prepare the refund request data
            capture_id = transaction.transaction_paypal_capture_id

            if not capture_id:
                return JsonResponse({"error": "Missing capture_id"}, status=400)
                
            # Verify transaction status
            if transaction.transaction_status != 'COMPLETED':
                return JsonResponse({
                    "error": f"Cannot refund transaction with status: {transaction.transaction_status}"
                }, status=400)

            # Get OAuth token first
            auth_url = "https://api.sandbox.paypal.com/v1/oauth2/token"
            client_id = clientId
            secret_key = secretKey
            credentials = f"{client_id}:{secret_key}"
            refund_amount = (transaction.transaction_amount * Decimal('0.95')).quantize(Decimal('0.01'), rounding=ROUND_DOWN)
            # Get access token
            auth_response = req.post(
                auth_url,
                headers={
                    "Authorization": f"Basic {base64.b64encode(credentials.encode()).decode()}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={"grant_type": "client_credentials"}
            )
            
            auth_response.raise_for_status()
            access_token = auth_response.json()['access_token']

            # Correct refund URL
            url = f"https://api.sandbox.paypal.com/v2/payments/captures/{capture_id}/refund"
            
            refund_data = {
                "amount": {
                    "currency_code": "PHP",
                    "value": str(refund_amount)
                },
                "note_to_payer": "Refund for transaction"
            }

            # Make the refund request with OAuth token
            response = req.post(
                url,
                json=refund_data,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Prefer": "return=representation"
                }
            )
            
            # Log the response for debugging
            logger.info(f"PayPal Refund Request Details:")
            logger.info(f"Capture ID: {capture_id}")
            logger.info(f"Amount: {transaction.transaction_amount}")
            logger.info(f"Response Status: {response.status_code}")
            logger.info(f"Response Content: {response.text}")
            
            response.raise_for_status()

            # Parse the PayPal response
            refund_response = response.json()

            # Update transaction status
            transaction.transaction_status = "REFUNDED"
            transaction.save()

            # Return success response
            return JsonResponse({
                "message": "Refund successful",
                "transaction_id": transaction.transaction_id,
                "order_id": transaction.order_id,
                "refund_id": refund_response.get('id', 'N/A'),
                "status": refund_response.get('status'),
                "amount": str(transaction.amount),
                "refund_date": timezone.now().isoformat()
            }, status=200)

        except req.exceptions.RequestException as e:
            logger.error(f"Refund failed: {str(e)}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                logger.error(f"PayPal error details: {e.response.text}")
            return JsonResponse({
                "error": "Refund request failed",
                "details": str(e),
                "transaction_id": transaction.transaction_id if transaction else None
            }, status=500)
        except Exception as e:
            logger.error(f"Error processing refund: {str(e)}")
            return JsonResponse({
                "error": "Internal server error",
                "details": str(e)
            }, status=500)

#jolito changes       
class ReportView(APIView):
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        print("Request data:", request.data)  # Debug: print incoming request data
        # Pass the request context to the serializer
        serializer = self.serializer_class(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            print("Serializer data is valid.")  # Debug: print when serializer data is valid
            report = serializer.save()  # Save the report instance
            print("Report created:", report)  # Debug: print the created report instance
            return Response(self.serializer_class(report).data, status=status.HTTP_201_CREATED)
        
        print("Serializer errors:", serializer.errors)  # Debug: print serializer errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class NotificationListView(APIView):
    authentication_classes = [JWTAuthentication]  # Specify your custom JWTAuthentication
    permission_classes = [permissions.IsAuthenticated]  # Ensure this is set to IsAuthenticated or a custom permission

    def get(self, request):

        notifications = Notification.objects.filter(recipient=request.user)
        serializer = NotificationSerializer(notifications, many=True, context={'request': request})

        return Response(serializer.data)

class MarkNotificationAsReadView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def patch(self, request, pk):
        try:
            print(f"Current user: {request.user}")  # Log the authenticated user
            notification = Notification.objects.get(notif_id=pk, recipient=request.user)
            print(f"Notification: {notification}")  # Log the notification details
            notification.notif_is_read = True

            
            notification.save()
            return Response({"message": "Notification marked as read"}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)

#jericho update
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def save_fcm_token(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_id = data.get('user_id')
        fcm_token = data.get('fcm_token')

        if not user_id or not fcm_token:
            return JsonResponse({'error': 'User ID and FCM token are required'}, status=400)

        # Save FCM token in the database (model to be created)
        UserAccount.objects.filter(id=user_id).update(fcm_token=fcm_token)

        return JsonResponse({'message': 'FCM Token saved successfully!'}, status=200)

@csrf_exempt
def remove_fcm_token(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_id = data.get('user_id')
        fcm_token = data.get('fcm_token')

        if not user_id or not fcm_token:
            return JsonResponse({'error': 'User ID and FCM token are required'}, status=400)
        
        if fcm_token == None:
            return JsonResponse({'message': 'No FCM Token to be removed'}, status=200)


        # Remove the FCM token from the database
        user = UserAccount.objects.filter(id=user_id, fcm_token=fcm_token).first()
        if user:
            user.fcm_token = None
            user.save()
            return JsonResponse({'message': 'FCM Token removed successfully!'}, status=200)
        else:
            return JsonResponse({'error': 'User not found or FCM Token mismatch'}, status=404)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

#jericho's rating update
class RateUserView(APIView):
    serializer_class = RatingSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        print("Request data:", request.data)  # Debug: print incoming request data

        # Get the authenticated user as the from_user
        from_user = request.user
        print("from user:", from_user.id)

        # Retrieve to_user_id from the request data
        to_user_id = request.data.get('to_user_id')
        if not to_user_id:
            return Response({"detail": "Missing 'to_user_id' in request data."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Validate and get the to_user using to_user_id
        try:
            to_user = get_object_or_404(UserAccount, id=to_user_id)
        except Http404:
            return Response({"detail": "No user found with the provided 'to_user_id'."},
                            status=status.HTTP_404_NOT_FOUND)

        # Check if a rating already exists
        rating_instance = Rating.objects.filter(from_user_id=from_user, to_user_id=to_user).first()

        # If a rating exists, update it
        if rating_instance:
            serializer = self.serializer_class(rating_instance, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()  # Update the existing rating
                print("Rating updated:", serializer.data)  # Debug: print the updated rating instance
                return Response(serializer.data, status=status.HTTP_200_OK)
            print("Serializer errors:", serializer.errors)  # Debug: print serializer errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # If no rating exists, create a new one
        request.data['from_user_id'] = from_user.id
        request.data['to_user_id'] = to_user_id
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            rating = serializer.save()  # Save the new rating instance
            print("Rating created:", rating)  # Debug: print the created rating instance
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        print("Serializer errors:", serializer.errors)  # Debug: print serializer errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RatingsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user.id
        print(f"Authenticated user: {user}")

        # Fetch ratings for the logged-in user where they are the 'to_user_id'
        ratings = Rating.objects.filter(to_user_id=user).order_by('-created_at')
        print(f"Ratings Queryset: {ratings}")

        # Serialize the ratings
        serializer = RatingSerializerView(ratings, many=True)
        print(f"Serialized Ratings: {serializer.data}")

        # Return an empty list if no ratings are found
        if not ratings.exists():
            return Response([], status=status.HTTP_200_OK)

        return Response(serializer.data, status=status.HTTP_200_OK)

class UserEditApplication(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user.id

        try:
            user_acc = UserAccount.objects.get(id=user)
            acc_serializer = UserRegisterSerializer(user_acc)
            user_profile = UserProfile.objects.get(user_id=user)
            profile_serializer = UserProfileSerializer(user_profile)

            return Response({'account': acc_serializer.data, 'profile': profile_serializer.data}, status=status.HTTP_200_OK)
        except UserAccount.DoesNotExist or UserProfile.DoesNotExist as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class UpdateUserApplication(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def is_base64(self, s):
        """Check if a string is valid Base64."""
        try:
            # Try decoding the string
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False

    def put(self, request):
        try:
            user_profile = UserProfile.objects.get(user_id=request.user.id)
            user_valid_id = request.data.get('user_prof_valid_id')
            user_picture = request.data.get('user_prof_valid_pic')

            prof_serializer = UserProfileSerializer(user_profile, data=request.data, partial=True)

            if prof_serializer.is_valid():
                prof_serializer.save()
                
                images = {
                    'valid_id': user_valid_id or user_profile.user_prof_valid_id,
                    'user_img': user_picture or user_profile.user_prof_valid_pic
                }

                folder_name = f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} ({request.user.id})"
                
                for key, img in images.items():
                    if self.is_base64(img):
                        try:
                        # format, imgstr = img.split(';base64,') 
                            ext = 'jpg'
                            
                            image_data = ContentFile(base64.b64decode(img), name=f"user{request.user.id}_{user_profile.user_prof_fname}_{user_profile.user_prof_lname}.{ext}")

                            upload_result = cloudinary.uploader.upload(image_data, folder=f"user_images/{folder_name}")

                            if key == 'valid_id':
                                user_profile.user_prof_valid_id = upload_result['secure_url']
                            elif key == 'user_img': 
                                user_profile.user_prof_valid_pic = upload_result['secure_url']

                        except Exception as e:
                            print(str(e))
                            return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
                        
                    else:
                        if key == 'valid_id':
                            user_profile.user_prof_valid_id = img
                        elif key == 'user_img':
                            user_profile.user_prof_valid_pic = img

            user_profile.save()
            user_app = UserApplication.objects.get(user_id=request.user.id)
            user_app.user_app_status = 'PENDING'
            user_app.save()

            reserialize = UserProfileSerializer(user_profile)

            return Response({'profile': reserialize.data, 'status': user_app.user_app_status}, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(str(e))

            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        #jericho update
class ReceivedReportsListView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        reports = Report.objects.filter(
            report_details__contains={'reported_user_id': str(request.user.id)},
            report_status='APPROVED'
        ).order_by('-updated_at')
        serializer = ViewReportSerializer(reports, many=True)
        return Response(serializer.data)


class SentReportsListView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        # Fetch reports where the logged-in user is the reporter
        reports = Report.objects.filter(
            report_details__contains={'reporter_id': str(request.user.id)}
        ).order_by('-updated_at')
        serializer = ViewReportSerializer(reports, many=True)
        return Response(serializer.data)


class ReportDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, report_id):
        try:
            report = Report.objects.get(id=report_id)
            # Assuming you have a ReportSerializer to format the data
            serializer = ViewReportSerializer(report)
            
            # Print the JSON data being returned
            print(serializer.data)  # This will print the JSON response to the console
            
            return Response(serializer.data)
        except Report.DoesNotExist:
            return Response({"error": "Report not found"}, status=status.HTTP_404_NOT_FOUND)
        
class TransactionDetails(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, order_id):
        try:
            order = ReservationInvoice.objects.get(order_id=order_id)
            order_serializer = ReservationInvoiceSerializer(order).data

            if order.offer_id:
                order_serializer['offer_price'] = order.offer_id.offer_price

            listing = Listing.objects.get(list_id=str(order.list_id))
            list_serializer = ListingSerializer(listing).data

            if order.order_status not in ['PAID', 'COMPLETED']:
                return Response({'order': order_serializer, 'listing': list_serializer}, status=status.HTTP_200_OK)

            trans = Transaction.objects.get(order_id=order.order_id)
            print(trans)
            trans_serializer = TransactionSerializer(trans).data

            print(trans_serializer)
            print(order_serializer)

            return Response({'transaction': trans_serializer, 'order': order_serializer, 'listing': list_serializer}, status=status.HTTP_200_OK)

        except Transaction.DoesNotExist or ReservationInvoice.DoesNotExist:
            return Response({'error': 'Transaction or Invoice not found.'}, status=status.HTTP_400_BAD_REQUEST)
        
class MarkCompleteTransaction(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, order_id):
        try:
            order = ReservationInvoice.objects.get(order_id=order_id)
            order.order_status = 'COMPLETED'
            order.save()

            if order.offer_id:
                offer = Offer.objects.get(offer_id=order.offer_id.offer_id)
                offer.offer_status = 'COMPLETED'
                offer.save()

            return Response({'message': order.order_status}, status=status.HTTP_200_OK)

        except ReservationInvoice.DoesNotExist:
            return Response({'error': 'Invoice not found.'}, status=status.HTTP_400_BAD_REQUEST)

class AssumptorCurrentTransaction(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        print(request.user)
        try:
            user = request.user
            statuses = ['PENDING', 'PAID']

            listings = Listing.objects.filter(user_id=user.id)

            print('ari na dapit')
            
            invoices = ReservationInvoice.objects.filter(list_id__in=listings.values_list('list_id', flat=True), order_status__in=statuses)
            print(invoices)

            if not invoices.exists():
                return Response({'invoices': []}, status=status.HTTP_200_OK)        
            
            invoice_serializer = ReservationInvoiceSerializer(invoices, many=True)

            for i, invoice in enumerate(invoice_serializer.data):
                listing = Listing.objects.get(list_id=str(invoice['list_id']))
                listing_serializer = ListingSerializer(listing).data
                invoice_serializer.data[i]['listing'] = listing_serializer
                

            return Response({'invoices': invoice_serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'error': f'An error occured: {e}'})

class AssumptorCompleteCancelledTransaction(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, inv_status):
        print(request.user)
        try:
            user = request.user

            listings = Listing.objects.filter(user_id=user.id)

            print('ari na dapit')
            
            invoices = ReservationInvoice.objects.filter(list_id__in=listings.values_list('list_id', flat=True), order_status=inv_status)
            print(invoices)

            if not invoices.exists():
                return Response({"invoices": []}, status=status.HTTP_200_OK)        
            
            invoice_serializer = ReservationInvoiceSerializer(invoices, many=True)

            for i, invoice in enumerate(invoice_serializer.data):
                listing = Listing.objects.get(list_id=str(invoice['list_id']))
                listing_serializer = ListingSerializer(listing).data
                invoice_serializer.data[i]['listing'] = listing_serializer
            
            return Response({'invoices': invoice_serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'error': f'An error occured: {e}'})

class AssumeeCompleteCancelledTransaction(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, inv_status):
        print(request.user)
        try:
            user = request.user

            
            invoices = ReservationInvoice.objects.filter(user_id=user.id, order_status=inv_status)
            print(invoices)

            if not invoices.exists():
                return Response({"invoices": []}, status=status.HTTP_200_OK)        
            
            invoice_serializer = ReservationInvoiceSerializer(invoices, many=True)

            for i, invoice in enumerate(invoice_serializer.data):
                listing = Listing.objects.get(list_id=str(invoice['list_id']))
                listing_serializer = ListingSerializer(listing).data
                invoice_serializer.data[i]['listing'] = listing_serializer
            
            return Response({'invoices': invoice_serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'error': f'An error occured: {e}'})

class AssumeeCurrentTransaction(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        print(request.user)
        try:
            user = request.user
            statuses = ['PENDING', 'PAID']

            print('ari na dapit')
            
            invoices = ReservationInvoice.objects.filter(user_id=user.id, order_status__in=statuses)
            print(invoices)

            if not invoices.exists():
                return Response({'invoices': []}, status=status.HTTP_200_OK)        
            
            invoice_serializer = ReservationInvoiceSerializer(invoices, many=True)

            for i, invoice in enumerate(invoice_serializer.data):
                listing = Listing.objects.get(list_id=str(invoice['list_id']))
                listing_serializer = ListingSerializer(listing).data
                invoice_serializer.data[i]['listing'] = listing_serializer
                

            return Response({'invoices': invoice_serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'error': f'An error occured: {e}'})

class MarkSoldListing(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]              

    def get(self, request, order_id):
        try:
            order = ReservationInvoice.objects.get(order_id=order_id, order_status='COMPLETED')

            try:
                listing = Listing.objects.get(list_id=str(order.list_id))
                listing.list_status = 'SOLD'
                listing.save()

                return Response({'message': listing.list_status}, status=status.HTTP_200_OK)
            except Listing.DoesNotExist:
                return Response({'error': 'Listing for this invoice does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        except ReservationInvoice.DoesNotExist:
            return Response({'error': 'Invoice not found.'}, status=status.HTTP_400_BAD_REQUEST)
        
class RequestPayout(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]  

    def post(self, request):
        user = request.user
        data = request.data.copy()
        data['user_id'] = user.id

        serializers = PayoutSerializer(data=data, context={'request': request})

        if serializers.is_valid(raise_exception=True):
            serializers.save()
            return Response({'payout': serializers.data}, status=status.HTTP_201_CREATED)
        print(serializers.errors)
        return Response({'error': str(serializers.errors)}, status=status.HTTP_400_BAD_REQUEST)
    
class PayoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]  

    def get(self, request, order_id):
        user = request.user
        
        payout = PayoutRequest.objects.filter(user_id=user.id, order_id=order_id).first()

        if not payout:
            return Response({'payout': {}}, status=status.HTTP_200_OK)

        serializers = PayoutSerializer(payout)

        if serializers:
            data = serializers.data
            profile = UserProfile.objects.get(user_id=payout.user_id)
            data['req_by'] = f'{profile.user_prof_fname} {profile.user_prof_lname}'
            data['payout_amnt'] = float(payout.order_id.order_price)
            data['fee'] = float(payout.order_id.order_price) * .05
            data['tot_payout'] = float(payout.order_id.order_price) * .95

            print(data)
            
            return Response({'payout': data}, status=status.HTTP_200_OK)
        # print(serializers.errors)
        return Response({'error': str(serializers.errors)}, status=status.HTTP_400_BAD_REQUEST)
    
class RequestRefund(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]  

    def post(self, request):
        user = request.user
        data = request.data.copy()
        data['user_id'] = user.id

        serializers = PayoutSerializer(data=data, context={'request': request})

        if serializers.is_valid(raise_exception=True):
            serializers.save()
            
            return Response({'payout': serializers.data}, status=status.HTTP_201_CREATED)
        print(serializers.errors)
        return Response({'error': str(serializers.errors)}, status=status.HTTP_400_BAD_REQUEST)

class RequestPayouts(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]  

    def post(self, request):
        user = request.user
        data = request.data.copy()
        data['user_id'] = user.id

        serializers = PayoutSerializer(data=data, context={'request': request})

        if serializers.is_valid(raise_exception=True):
            serializers.save()
            return Response({'payout': serializers.data}, status=status.HTTP_201_CREATED)
        print(serializers.errors)
        return Response({'error': str(serializers.errors)}, status=status.HTTP_400_BAD_REQUEST)
    