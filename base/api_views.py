import requests, base64, cloudinary
from smtplib import SMTPConnectError, SMTPException
# from django.contrib.auth.decorators import user_passes_test
from django.utils import timezone
from django.http import JsonResponse
from django.db.models import F, Max, OuterRef, Subquery, Q, Case, When
# from .permissions import IsAdminUser
from .models import UserProfile, UserVerification, ChatRoom, ChatMessage
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


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class UserRegister(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            refresh_token = RefreshToken.for_user(user)
            access_token = str(refresh_token.access_token)
            
            return Response({'access': access_token, 'refresh': str(refresh_token), 'user': UserRegisterSerializer(user).data}, status=status.HTTP_201_CREATED)
        return Response({'error': serializer.error}, status=status.HTTP_400_BAD_REQUEST)

class UserCreateProfile(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = UserProfileSerializer(data=request.data)
        user_valid_id = request.data.get('user_prof_valid_id')
        user_picture = request.data.get('user_prof_pic')

        if serializer.is_valid(raise_exception=True):
            user_profile = serializer.save()

            user = user_profile.user_id

            if not user.is_active:
                user.is_active = True
                user.save()

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
                    user_profile.user_prof_pic = uploaded_images[1]
                else:
                    return JsonResponse({'error': 'Image upload failed.'}, status=status.HTTP_400_BAD_REQUEST)
                
                user_profile.save()

            except Exception as e:
                return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
            reserializer = UserProfileSerializer(user_profile)
            return Response({'user_profile': reserializer.data}, status=status.HTTP_201_CREATED)

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

            return Response({'detail': 'Email has been verified.'}, status=status.HTTP_200_OK)

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
        serializer = UserLoginSerializer(data=data)
        
        if serializer.is_valid(raise_exception=True):
            user = serializer.check_user(data)
            refresh_token = RefreshToken.for_user(user)
            access_token = str(refresh_token.access_token)

            user_role = {
                'is_admin': user.is_staff,
                'is_reviewer': user.is_reviewer,
                'is_assumee': user.is_assumee,
                'is_assumptor': user.is_assumptor
            }

            if not user.is_staff or user.is_reviewer:
                try:
                    user_prof = UserProfile.objects.get(user_id=user)
                    user_app = UserApplication.objects.get(user_prof_id=user_prof)
                    is_approved = user_app.user_app_status
                except UserProfile.DoesNotExist:
                    is_approved = False
                except UserApplication.DoesNotExist:
                    is_approved = False

            login(request, user)
            return Response({'access': access_token, 'refresh': str(refresh_token), 'user_role': user_role, 'user': {'user_id': user.id, 'email': user.email, 'is_approved': is_approved}}, status=status.HTTP_200_OK)
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
    
class UserGoogleLogin(APIView):
    def post(self, request):
        serializer = UserGoogleLoginSerializer(data=request.data)
        
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data['email']
            user = serializer.check_user(email)
            token, created = Token.objects.get_or_create(user=user)

            return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_200_OK)
        
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
    
class UserLogout(APIView):
    def post(self, request):
        logout(request)
        return Response(status=status.HTTP_200_OK)

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

class ViewOtherProfile(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, user_id):
        try:
            user_profile = UserProfile.objects.get(user_id=user_id)
            prof_serializer = UserProfileSerializer(user_profile)

            return Response({'user_profile': prof_serializer.data}, status=status.HTTP_200_OK)
        except UserModel.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
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

    def get(self, request, chatroom_id):
        # print(receiver_id)
        try:
            user_id = request.user.id
            room_id = chatroom_id

            room = ChatRoom.objects.get(chatroom_id=room_id)
            room_messages = ChatMessage.objects.filter(chatroom_id=room)\
            .order_by('chatmess_created_at')\
            .values('sender_id', 'chatmess_content', 'chatmess_created_at', 'chatmess_is_read')
                    # serializer = MessageSerializer(room_messages, many=True)

            # print(room_messages)

            return Response({'messages': list(room_messages)}, status=status.HTTP_200_OK)
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

        existing_offer = Offer.objects.filter(list_id__user_id=receiver_id, user_id=user, offer_status__in=['PENDING', 'ACCEPTED']).first()

        if existing_offer:
            print(existing_offer)
            return Response({
                'error': 'You still have an active offer for this listing.'
            }, status=status.HTTP_400_BAD_REQUEST)


        try:
            try:
                receiver = UserModel.objects.get(pk=receiver_id)
            except UserModel.DoesNotExist:
                return Response({'error': 'Recipient not found.'}, status=status.HTTP_404_NOT_FOUND)
            
            chat_content = f'Made an offer: ₱{price}'
            
            chat_room, created = ChatRoom.objects.get_or_create(
                chatroom_user_1=max(user, receiver, key=lambda u: u.id),
                chatroom_user_2=min(user, receiver, key=lambda u: u.id),
                defaults={'chatroom_last_message': chat_content}
            )

            chat_room.chatroom_last_message = chat_content
            chat_room.save()


            chat_message_data = {
                'chatmess_content': chat_content,
                'sender_id': user.id,
                'chatroom_id': chat_room.chatroom_id
            }

            Offer.objects.create(offer_price=price, list_id=list, user_id=user)

            serializer = MessageSerializer(data=chat_message_data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)                

        except Exception as e:
            print(str(e))
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateOfferAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def put(self, request):
        offer_id = request.data.get('offer_id')
        offer_amnt = request.data.get('offer_amnt')

        try:
            offer = Offer.objects.get(offer_id=offer_id)

            if offer.offer_status != 'PENDING':
                return Response({'error': 'Cannot change offer amount'}, status=status.HTTP_400_BAD_REQUEST)
            
            offer.offer_price = offer_amnt
            offer.save()

            return Response({})

        except Offer.DoesNotExist:
            return Response({'error': 'Offer not found'}, status=status.HTTP_400_BAD_REQUEST)
        

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
                offer_status__in=['PENDING', 'ACCEPTED']
                ).select_related('list_id__user_id__profile').order_by('-offer_created_at').first()
            
            if lastest_active_offer:
                offer = OfferSerializer(lastest_active_offer).data
                listing = CarListingSerializer(lastest_active_offer.list_id).data
                lister = lastest_active_offer.list_id.user_id.profile
                lister_prof = UserProfileSerializer(lister).data

                print(offer)
                print(lister_prof)
                print(listing)

                return Response({'offer': offer, 'listing': listing, 'lister_profile': lister_prof}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'No active offers found'}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            print(str(e))
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# class rejectOffer

class GetListingOfferAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, receiver_id):
        receiver_id = receiver_id
        print(request.user.id)
        print(receiver_id)
        try:
            user = request.user

            lastest_active_offer = Offer.objects.filter(user_id=receiver_id,
                list_id__user_id=user.id,
                offer_status__in=['PENDING', 'ACCEPTED']
                ).select_related('list_id__user_id__profile').order_by('-offer_created_at').first()
            
            if lastest_active_offer:
                offer = OfferSerializer(lastest_active_offer).data
                listing = CarListingSerializer(lastest_active_offer.list_id).data
                lister = lastest_active_offer.list_id.user_id.profile
                lister_prof = UserProfileSerializer(lister).data

                return Response({'offer': offer, 'listing': listing, 'lister_profile': lister_prof}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'No active offers found'}, status=status.HTTP_404_NOT_FOUND)
            
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
        ).order_by('-chatmess_created_at').values('sender_id')[:1])
            ).values('chatmate', 'chatroom_id', 'chatroom_last_message', 'last_message_date', 'last_sender_id')
                        
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
                    'sender_id': room['last_sender_id']
                })
            
            inbox = sorted(inbox, key=lambda x: x['last_message_date'], reverse=True)

            # print(chatmates)
            # print(user_id)
            # print(inbox)

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
        self.perform_create(serializer)
        
        # Fetch the user's wallet (modify the wall_id as needed)
        # wallet = Wallet.objects.get(wall_id=1)  # You may want to get the user's wallet dynamically
        # required_coins = Decimal('20')  # Coins needed to add a listing

        # if wallet.wall_amnt < required_coins:
        #     return Response(
        #         {'detail': 'Insufficient coins, Please top to proceed'},
        #         status=status.HTTP_400_BAD_REQUEST
        #     )

        # # Deduct coins from the wallet
        # wallet.wall_amnt -= required_coins
        # wallet.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    def perform_create(self, serializer):
        # Assign the user from the request to the user_id field
        serializer.save(user_id=self.request.user)
        # You can set additional fields or perform actions before saving

@method_decorator(csrf_exempt, name='dispatch')
class CarListingByCategoryView(APIView):
    serializer_class = CarListingSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def get_queryset(self):
        category = self.kwargs.get('category')
        return Listing.objects.filter(list_content__category=category)

    def get(self, request, category, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)

@method_decorator(csrf_exempt, name='dispatch')   
class ListingDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication] 

    def get(self, request, list_id, *args, **kwargs):
        listing = get_object_or_404(Listing, list_id=list_id)
        serializer = CarListingSerializer(listing)
        # print(serializer.data)
        return Response(serializer.data)

class AdminRegistrationAPIView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    # permission_classes = [IsAdminUser]
    def post(self, request):
        serializer = AdminRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            account, profile = serializer.save()

            password = serializer.generate_password()

            # return Response({
            #     'admin': {
            #         'email': account.email,
            #         'first_name': account.first_name,
            #         'last_name': account.last_name
            #     },
            #     'profile': {
            #         'fname': profile.user_profile_fname,
            #         'lname': profile.user_prof_lname,
            #         'gender': profile.user_prof_gender,
            #         'dob': profile.user_prof_dob,
            #         'contact': profile.user_prof_mobile,
            #         'address': profile.user_prof_address
            #     },
            #     'password': password
            # }, status=status.HTTP_201_CREATED)
            return Response({'message': 'Admin Created Succesfully.'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


def is_admin(user):
    return user.is_staff

###### render views ######