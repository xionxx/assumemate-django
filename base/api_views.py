import requests, base64, cloudinary
from smtplib import SMTPConnectError, SMTPException
from django.contrib.auth.decorators import user_passes_test
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views.decorators.http import require_POST
from .permissions import IsAdminUser
from .models import Message, UserProfile, UserVerification
from .serializers import *
from rest_framework import viewsets, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.core.files.base import ContentFile
from rest_framework.authtoken.models import Token
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from django.contrib.auth import login as login, authenticate, logout
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import update_last_login


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
            return Response({'access': access_token, 'refresh': str(refresh_token), 'user_role': user_role, 'user': {'email': user.email, 'is_approved': is_approved}}, status=status.HTTP_200_OK)
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
        except UserModel.DoesNotExist:
            return Response({'error': 'User account not found.'}, status=status.HTTP_404_NOT_FOUND)
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
            print(e)
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ChangePasswordAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def put(self, request):
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



class AdminRegistrationAPIView(APIView):
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




        



def conversation(request):
    messages = Message.objects.all().order_by('mess_date')

    serializer = MessageSerializer(messages, many=True)

    return render(request, 'base/home.html', {'messages': messages})

@require_POST
def send_message(request):
    sender = request.Account  # Assuming the logged-in user is the sender
    content = request.POST['content']
    
    Message.objects.create(sender_id=sender, mess_content=content)
    return redirect('conversation')


def is_admin(user):
    return user.is_staff

###### render views ######.
def base(request):
    return render(request, "base/base.html")

# @user_passes_test(is_admin)
def admin_acc_create(request):
    return render(request, 'base/add_admin.html')

def admin_acc_list(request):
    admin = UserModel.objects.filter(is_staff=True)
    context = {'admin': admin, 'nav': 'admin'}
    # context = {'nav': 'admin'}
    return render(request, 'base/admin_list.html', context)