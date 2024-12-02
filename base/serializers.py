import os
import re
from dotenv import load_dotenv
import secrets, string
from django.db.models import Q
from django.db import IntegrityError
from django.utils import timezone
from datetime import timedelta
from django.core.mail import EmailMessage
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from django.contrib.auth.hashers import check_password
from google.auth.transport import requests
from google.oauth2 import id_token as token_auth
from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator    
from django.contrib.sites.shortcuts import get_current_site

load_dotenv()
UserModel = get_user_model()

class PromoteListingSerializer(serializers.ModelSerializer):
    class Meta:
        model = PromoteListing
        fields = ['list_id']  # Adjust fields as necessary

class UserRegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    google_id = serializers.CharField(max_length=255, required=False, allow_blank=True)
    password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = UserModel
        fields = ['id', 'email', 'password', 'google_id', 'is_staff', 'is_reviewer', 'is_assumee', 'is_assumptor']

    def validate(self, attrs):
        google_id = attrs.get('google_id')
        password = attrs.get('password')
        
        if google_id:
            if UserModel.objects.filter(google_id=google_id).exists():
                raise serializers.ValidationError('Google account already connected to an existing user.')
        
        elif not password:
            raise serializers.ValidationError('Password is required.')
        
        return attrs

    def create(self, validated_data):
        email = validated_data['email']
        google_id = validated_data.get('google_id')
        password = validated_data.get('password')
        requires_verification = not validated_data.get('is_staff', False) or validated_data.get('is_reviewer', False)

        if requires_verification and not google_id:
            try:
                email_verified_user =  UserVerification.objects.get(user_verification_email=email, user_verification_is_verified=True)
            except UserVerification.DoesNotExist:
                raise serializers.ValidationError('Email has not been verified yet.')
            
        if google_id:
            user_obj = UserModel.objects.create_user(email=email, google_id=google_id)
        else:
            user_obj = UserModel.objects.create_user(email=email, password=password)

        user_obj.is_staff = validated_data.get('is_staff', False)
        user_obj.is_assumee = validated_data.get('is_assumee', False)
        user_obj.is_assumptor = validated_data.get('is_assumptor', False)
        user_obj.is_reviewer = validated_data.get('is_reviewer', False)
        user_obj.save()

        if requires_verification and not google_id:
            email_verified_user.user_id = user_obj
            email_verified_user.save()

        # if user_obj.is_assumptor:
        #     Wallet.objects.create(user_id=user_obj)

        Wallet.objects.create(user_id=user_obj)

        return user_obj
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)

        if password:
            instance.set_password(password)

        instance.is_staff = validated_data.get('is_staff', instance.is_staff)
        instance.is_assumee = validated_data.get('is_assumee', instance.is_assumee)
        instance.is_assumptor = validated_data.get('is_assumptor', instance.is_assumptor)
        instance.is_reviewer = validated_data.get('is_reviewer', instance.is_reviewer)
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.save()

        return instance
    
class AdminRegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    firstname = serializers.CharField(source='first_name')
    lastname = serializers.CharField(source='last_name')
    gender = serializers.CharField()
    dob = serializers.DateField()
    phone_number = serializers.CharField(source='contact')
    address = serializers.CharField()
    # imagefile = serializers.ImageField(required=False)
    
    def generate_password(self, length=12):
        """Generate a secure random password."""
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for i in range(length))
        return password
    
    def create(self, validated_data):
        email = validated_data['email']
        password = self.generate_password()

        try: 
            admin_acc = UserModel.objects.create(email=email, is_staff=True, is_active=True)
            admin_acc.set_password(password)
            admin_acc.save()

            admin_profile = UserProfile.objects.create(user_prof_fname=validated_data['first_name'], user_prof_lname=validated_data['last_name'], 
                                                    user_prof_gender=validated_data['gender'], user_prof_dob=validated_data['dob'],
                                                    user_prof_mobile=validated_data['contact'], user_prof_address=validated_data['address'], user_id=admin_acc)
            
            return admin_acc, admin_profile
        except IntegrityError:
            raise serializers.ValidationError({'message': 'User with this email already exist'})
        except Exception as e:
            raise serializers.ValidationError({'message' :str(e)})


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['user_prof_lname', 'user_prof_fname', 'user_prof_gender', 
                  'user_prof_dob', 'user_prof_mobile', 'user_prof_address', 'user_prof_valid_id', 'user_prof_pic']
        read_only_fields = ['user_id', 'user_prof_valid_id', 'user_prof_pic']

    def validate_user_prof_mobile(self, value):
        pattern = r'^\+639\d{9}$'
        
        if value.startswith('09'):
            value = '+63' + value[1:]
        elif value.startswith('9'):
            value = '+63' + value
        elif value.startswith('63'):
            value = '+' + value
        
        if not re.match(pattern, value):
            raise serializers.ValidationError("Please enter a valid Philippine mobile number in the format +639XXXXXXXXX")
        
        return value

    def to_title_case(self, value):
        return value.title() if isinstance(value, str) else value

    def create(self, validated_data):
        validated_data['user_prof_fname'] = self.to_title_case(validated_data.get('user_prof_fname'))
        validated_data['user_prof_lname'] = self.to_title_case(validated_data.get('user_prof_lname'))
        validated_data['user_prof_gender'] = self.to_title_case(validated_data.get('user_prof_gender'))
        validated_data['user_prof_address'] = self.to_title_case(validated_data.get('user_prof_address'))
        validated_data['user_prof_mobile'] = self.validate_user_prof_mobile(validated_data.get('user_prof_mobile'))

        user = super().create(validated_data)
        return user

    def update(self, instance, validated_data):
        if 'user_prof_mobile' in validated_data:
            validated_data['user_prof_mobile'] = self.validate_user_prof_mobile(validated_data['user_prof_mobile'])

        instance.user_prof_fname = self.to_title_case(validated_data.get('user_prof_fname', instance.user_prof_fname))
        instance.user_prof_lname = self.to_title_case(validated_data.get('user_prof_lname', instance.user_prof_lname))
        instance.user_prof_gender = self.to_title_case(validated_data.get('user_prof_gender', instance.user_prof_gender))
        instance.user_prof_address = self.to_title_case(validated_data.get('user_prof_address', instance.user_prof_address))
        instance.user_prof_dob = validated_data.get('user_prof_dob', instance.user_prof_dob)
        instance.user_prof_mobile = validated_data.get('user_prof_mobile', instance.user_prof_mobile)
        instance.save()

        return instance

class CheckUserVerifiedSerializer(serializers.Serializer):
    user_verification_email = serializers.EmailField()

    def check_verification_status(self):
        email = self.validated_data.get('user_verification_email')
        user_verification = get_object_or_404(UserVerification, user_verification_email=email)

        return user_verification.user_verification_is_verified, user_verification.user_id
    
class EmailVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserVerification
        fields = ['user_verification_email', 'user_verification_code']
    
    def create(self, validated_data):
        email = validated_data['user_verification_email']
        
        return UserVerification.objects.create(user_verification_email=email, 
                                                            user_verification_expires_at=timezone.now() + timedelta(hours=24))
    
    def check_email(self, email):
        if UserModel.objects.filter(email=email).exists():
            raise serializers.ValidationError('User with this email already exists.')
        
        verification_record = UserVerification.objects.filter(user_verification_email=email, user_verification_is_verified=False).first()
        if verification_record:
            return verification_record
    
    def send_verification_email(self, request, email, verification_code):
        base_url = os.getenv('API_URL')
        verification_key = f'{base_url}/api/email-verify/{verification_code}/'
        html_msg = f"""
        <html>
        <body>
            <h2>Welcome  to register ASSUMATE ! Please confirm !</h2>
            <p>You are about to register to ASSUMATE account with {email}. Please click the 'Activate now' to verify your email address.</p>
            <a href="{verification_key}" style="
                display: inline-block;
                padding: 10px 20px;
                font-size: 16px;
                color: #ffffff;
                background-color: #4A8AF0;
                text-decoration: none;
                border-radius: 5px;
                text-align: center;
            ">Activate now</a>
            <p>If the button does not respond, please verify your email using the link below:</p></br>
            <p><a href="{verification_key}">{verification_key}</a></p></br>
            <p>For security reasons, the link will be only valid for 24 hours. After 24 hours, 
            you will need to register again. Thank you for supporting ASSUMATE</p>
            <p>If this is not you, please ignore this message.</p>
        </body>
        </html>"""

        email_message = EmailMessage(
        subject='ASSUMATE Account - Email address verification',
        body=html_msg,
        from_email=settings.EMAIL_HOST_USER,
        to=[email],
            )
        
        email_message.content_subtype = "html"

        email_message.send(fail_silently=False)

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def check_user(self, validated_data):
        user = UserModel.objects.filter(email=validated_data['email']).first()

        if not user:
            raise serializers.ValidationError({'error': 'Incorrect email or password'})
        
        if not user.has_usable_password():
            raise serializers.ValidationError({'error': 'Your account is connected to Google: Use the Google button to login'})
        
        if not check_password(validated_data['password'], user.password):
                raise serializers.ValidationError({'error': 'Incorrect email or password'})
        
        if user and not user.is_active:
            user.is_active = True
            user.save()
        
        authenticated_user = authenticate(username=validated_data['email'], password=validated_data['password'])

        if not authenticated_user:
            raise serializers.ValidationError({'error': 'Incorrect email or password hehe'})

        return authenticated_user
               
    
    # def to_representation(self, instance):
    #     user = self.check_user(self.validated_data)
    #     return {
    #         'email': user.email,
    #         'is_reviewer': user.is_reviewer,
    #         'is_assumee': user.is_assumee,
    #         'is_assumptor': user.is_assumptor
    #     }
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        model = PasswordResetToken
        read_only_fields = ['reset_token', 'user', 'reset_token_expires_at', 'reset_token_created_at']
        # read_only_fields = ['reset_token', 'reset_token_expires_at', 'reset_token_created_at']
    
    def check_user(self, email):
        try:
            user = UserModel.objects.get(email=email)
            return user
        except UserModel.DoesNotExist:
            raise serializers.ValidationError('User not found.')
    
    def create_token(self, email):
        user = self.check_user(email)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        expires_at =timezone.now() + timedelta(hours=1)

        reset_token, created = PasswordResetToken.objects.update_or_create(
            user=user,
            defaults={
                'reset_token': token,
                'reset_token_expires_at': expires_at,
                'reset_token_created_at': timezone.now()
            }
        )

        return user.profile.user_prof_fname, uidb64, reset_token.reset_token

    def send_reset_link(self, email):
        base_url = os.getenv('API_URL')
        template_name  = 'base/reset_link_template.html'
        name, uidb64, token = self.create_token(email)
        reset_link = f'{base_url}/reset-password?key={uidb64}&token={token}'
        context = {'name': name, 'link': reset_link}
        email_content =  render_to_string(
            template_name=template_name,
            context=context
            )
        
        email_message = EmailMessage(
        subject='[ASSUMATE Account] Password reset request',
        body=email_content,
        from_email=settings.EMAIL_HOST_USER,
        to=[email],
            )
        
        email_message.content_subtype = "html"

        email_message.send(fail_silently=False)
    
class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ['sender_id', 'chatroom_id', 'chatmess_content', 'chatmess_created_at', 'chatmess_is_read']

class ChatRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatRoom
        fields = ['chatroom_id', 'chatroom_user_1', 'chatroom_user_2', 'chatroom_last_message']

class ChatUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fieds = ['user_prof_lname', 'user_prof_fname', 'user_prof_pic', 'user_id']    
    
class UserGoogleLoginSerializer(serializers.Serializer):
    token = serializers.CharField()

    def check_user(self, validated_data):
        token = validated_data.get('token')

        try:
            clientId = os.getenv('OAUTH_CLIENT_ID')

            print(clientId)
            
            id_info = token_auth.verify_oauth2_token(token, requests.Request(), clientId)

            google_id = id_info['sub']
            email = id_info['email']

            user = UserModel.objects.filter(Q(google_id=google_id) & Q(email = email)).first()

            if not user:
                raise serializers.ValidationError({'error': 'No user associated with the google found'})

            if not user.is_active:
                user.is_active = True
                user.save()
            
            return user

        except ValueError as e:
            raise serializers.ValidationError({'error': f'Invalid token: {e}'})


# class GoogleSignInCheckSerializer(serializers.Serializer):
#     google_id = serializers.CharField(max_length=255, required=False)
#     email = serializers.EmailField(required=False)

#     def validate(self, attrs):
#         if not attrs.get('google_id') and not attrs.get('email'):
#             raise serializers.ValidationError('Google ID and Email are required.')

#         return attrs

#     def check_email(self):
#         google_id = self.validated_data.get('google_id')
#         email = self.validated_data.get('email')

#         user = None
#         if google_id:
#             user = UserModel.objects.filter(google_id=google_id).first()
        
#         if email:
#             user = UserModel.objects.filter(email=email).first()

#         exists = user is not None

#         return exists, self.validated_data

# class GoogleSignInCheckSerializer(serializers.Serializer):
#     token = serializers.CharField()

#     def validate(self, attrs):
#         token = attrs.get('token')
#         id_info = self.validate_token(token)
        
#         attrs['google_id'] = id_info.get('sub')
#         attrs['email'] = id_info.get('email')

#         print(attrs['google_id'])

#         return attrs

#     def validate_token(self, token):
#         clientId = os.getenv('CLIENT_ID')
        
#         try:
#             request = requests.Request()
            
#             id_info = token_auth.verify_oauth2_token(token, request, clientId)
#             print(id_info)
        
#             email = id_info.get('email')
#             google_id = id_info.get('sub')

#             print(google_id)

#             if 'email' not in id_info or 'sub' not in id_info:
#                 raise serializers.ValidationError("Token is missing required fields.")

#             return id_info
#         except ValueError:
#             raise serializers.ValidationError("Invalid ID token")

#     def check_email(self):
#         google_id = self.validated_data.get('google_id')
#         email = self.validated_data.get('email')

#         print(google_id)

#         user = UserModel.objects.filter(google_id=google_id).first() or UserModel.objects.filter(email=email).first()

#         exists = user is not None

#         return exists, self.validated_data

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user) 

        token['email'] = user.email
        token['user_id'] = user.id

        return token
    
class CarListingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Listing
        fields = '__all__'

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['wall_amnt']
        read_only_fields=['user_id']

class ListingSerializer(serializers.ModelSerializer):

    class Meta:
        model = Listing
        fields = '__all__' # Include other fields as necessary

class FavoriteSerializer(serializers.ModelSerializer):
    list_id = ListingSerializer()
    assumptor_id = UserProfileSerializer(source='user_id.userprofile', read_only=True)  # Ensure this is correct

    class Meta:
        model = Favorite
        fields = '__all__'

class FavoriteMarkSerializer(serializers.ModelSerializer):

    class Meta:
        model = Favorite
        fields = '__all__'



class FollowSerializer(serializers.ModelSerializer):
    class Meta:
        model = Follow
        fields = ['follower_id', 'following_id']

class ReservationInvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReservationInvoice
        fields = '__all__'

#jolito changes
class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['report_details', 'report_reason', 'report_status', 'updated_at']
    def validate(self, attrs):
        # Custom validation to ensure 'reported_user_id' is in report_details
        report_details = attrs.get('report_details', {})
        if 'reported_user_id' not in report_details:
            raise serializers.ValidationError("Reported user ID must be included.")
        return attrs
    def create(self, validated_data):
        return super().create(validated_data)

class PromoteListingDetailSerializer(serializers.ModelSerializer):
    list_id = ListingSerializer()  # Nested Listing details
    user_profile = serializers.SerializerMethodField()

    class Meta:
        model = PromoteListing
        fields = '__all__'

    def get_user_profile(self, obj):
        user = obj.list_id.user_id  # Access user_id from Listing
        user_profile = UserProfile.objects.filter(user_id=user).first()
        if user_profile:
            return UserProfileSerializer(user_profile).data
        return None


class PayoutSerializer(serializers.ModelSerializer):
    class Meta:
        model = PayoutRequest
        fields = ['payout_id', 'payout_paypal_email', 'order_id', 'user_id', 'payout_status', 'payout_created_at', 'payout_updated_at']
        read_only_fields = ['payout_id', 'payout_status', 'payout_created_at', 'payout_updated_at']

    def validate(self, data):
        # Check if a payout request already exists for the given order
        if PayoutRequest.objects.filter(order_id=data['order_id']).exists():
            raise serializers.ValidationError({'error': 'A payout request for this order already exists.'})
        
        order = data['order_id']
        order = ReservationInvoice.objects.get(order_id=order.order_id)
        if order.list_id.user_id != self.context['request'].user:
            raise serializers.ValidationError({'error': 'You are not authorized to request a payout for this order.'})

        return data
    
class RefundSerializer(serializers.ModelSerializer):
    class Meta:
        model = RefundRequest
        fields = ['refund_id', 'refund_status', 'refund_created_at', 'refund_updated_at', 'order_id', 'user_id']
        read_only_fields = ['refund_id', 'refund_created_at', 'refund_updated_at']

    def validate(self, data):
        if RefundRequest.objects.filter(order_id=data['order_id']).exists():
            raise serializers.ValidationError({'error': 'A refund request for this order already exists.'})
        
        order = data['order_id']
        order = ReservationInvoice.objects.get(order_id=order.order_id)
        if order.list_id.user_id != self.context['request'].user:
            raise serializers.ValidationError({'error': 'You are not authorized to request a refund for this order.'})

        return data

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = '__all__'

class NotificationSerializer(serializers.ModelSerializer):
    triggered_by_profile_pic = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = [
            'notif_id',
            'notif_message',
            'notif_created_at',
            'notif_is_read',
            'recipient',
            'list_id',
            'triggered_by',
            'notification_type',
            'follow_id',
            'triggered_by_profile_pic', 
                ]

    def get_triggered_by_profile_pic(self, obj):
       
        if obj.triggered_by:
            user_profile = obj.triggered_by.profile  
            if user_profile and user_profile.user_prof_pic:  
                return user_profile.user_prof_pic 
        return None
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        created_at = instance.notif_created_at
        formatted_created_at = created_at.strftime("%B %d, %Y at %I:%M %p")
        data['notif_created_at'] = formatted_created_at
        return data
    
#jericho's serializers.py
class RatingSerializer(serializers.ModelSerializer):
    from_user_id = UserProfileSerializer(source='from_user_id.profile', read_only=True)  # Correctly reference profile
    rating_value = serializers.FloatField()

    class Meta:
        model = Rating
        fields = ['from_user_id', 'to_user_id', 'rating_value', 'review_comment']

class RatingSerializer(serializers.ModelSerializer):
    # from_user_id = UserProfileSerializer(source='from_user_id.profile', read_only=True)  # Correctly reference profile
    rating_value = serializers.FloatField()

    class Meta:
        model = Rating
        fields = ['from_user_id', 'to_user_id', 'rating_value', 'review_comment']

#joselito's cchanges
class RatingSerializerView(serializers.ModelSerializer):
    from_user_id = UserProfileSerializer(source='from_user_id.profile', read_only=True)  # Correctly reference profile
    rating_value = serializers.FloatField()

    class Meta:
        model = Rating
        fields = ['from_user_id', 'to_user_id', 'rating_value', 'review_comment']


###############################
###############################
class OfferSerializer(serializers.ModelSerializer):
    class Meta:
        model = Offer
        # fields = ['offer_id', 'offer_price', 'user_id', 'list_id', '']
        fields = '__all__'

        
class ViewReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['report_id', 'report_reason', 'report_status', 'updated_at', 'details']
        extra_kwargs = {
            'details': {'source': 'report_details'}
        }