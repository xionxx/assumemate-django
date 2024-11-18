from datetime import timedelta
from django.utils import timezone
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db.models.signals import post_save
from django.dispatch import receiver

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, google_id=None):
        """
        Create and return a regular user with an email and password.
        """
        if not email:
            raise ValueError('An Email field must be set')
        email = self.normalize_email(email)

        user = self.model(email=email, google_id=google_id)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save()

        return user

class UserAccount(AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True, blank=True, null=True)
    google_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    is_reviewer = models.BooleanField(default=False)
    is_assumee = models.BooleanField(default=False)
    is_assumptor = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.email
    
class UserProfile(models.Model):
    user_prof_fname = models.CharField(max_length=50)
    user_prof_lname = models.CharField(max_length=50)
    user_prof_gender = models.CharField(max_length=6)
    user_prof_dob = models.DateField()
    user_prof_mobile = models.CharField(max_length=13)
    user_prof_address = models.CharField(max_length=255)
    user_prof_pic = models.URLField(null=True, blank=True)
    user_prof_valid_id = models.URLField(null=True, blank=True)
    user_id = models.OneToOneField(UserAccount, null=False, primary_key=True, editable=False, on_delete=models.CASCADE, db_column='user_id', related_name='profile')

    def __str__(self):
        return f"{self.user_prof_fname} {self.user_prof_lname}"

    class Meta:
        db_table = 'user_profile'

class UserVerification(models.Model):
    user_verification_id = models.BigAutoField(primary_key=True, editable=False)
    user_verification_email = models.EmailField(unique=True)
    user_verification_code = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user_verification_is_verified = models.BooleanField(default=False)
    user_verification_created_at = models.DateTimeField(auto_now_add=True)
    user_verification_expires_at = models.DateTimeField()
    user_id = models.OneToOneField(UserAccount, null=True, blank=True, on_delete=models.SET_NULL, related_name='email_verifications', db_column='user_id')

    def __str__(self):
        return f"Verification for {self.user_id.email}: {self.user_verification_is_verified}"
    
    class Meta:
        db_table = 'user_verification'

class UserApplication(models.Model):
    user_id = models.OneToOneField(UserAccount, null=False, on_delete=models.CASCADE, db_column='user_id', related_name='user_application', primary_key=True, editable=False)
    user_app_status = models.CharField(max_length=10, default='PENDING')
    user_app_approved_at = models.DateTimeField(blank=True, null=True)
    user_app_reviewer_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, blank=True, null=True, db_column='user_app_reviewer_id')

    class Meta:
        db_table = 'user_application'

class Listing(models.Model):
    list_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    list_content = models.JSONField(null=True, blank=True)
    list_status = models.CharField(max_length=20, default="PENDING")
    list_duration = models.DateTimeField(null=True, blank=True) 
    user_id = models.ForeignKey(UserAccount, null=True, blank=True, on_delete=models.PROTECT, db_column='user_id', related_name='listing')

    def __str__(self):
        return str(self.list_id)

    class Meta:
        db_table = 'listing'

class Report(models.Model):
    report_id = models.AutoField(primary_key=True)
    report_details = models.JSONField(null=True)
    reviewer = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='reviewed_reports', db_column='user_id')
    updated_at = models.DateTimeField(default=timezone.now)
    report_status =  models.CharField(max_length=20, default='PENDING')  # E.g., Approved, Pending, Declined
    report_reason = models.CharField(max_length=255, null=True)

    def check_suspension(self):
        # Get the reported user ID and the user ID who reported
        reported_user_id = self.report_details.get('reported_user_id')
        reporter_id = self.report_details.get('user_id')
        
        if not reported_user_id:
            return

        # Count approved reports for the reported user, excluding reports from the same reporter
        approved_reports = Report.objects.filter(
            report_details__reported_user_id=reported_user_id,
            report_status='APPROVED'
        ).exclude(report_details__user_id=reporter_id).count()

        # Set the threshold for suspension
        if approved_reports >= 3:  # Customize threshold
            # Check if the user is already suspended
            if not SuspendedUser.objects.filter(user_id=reported_user_id).exists():
                # Suspend the user if not already suspended
                suspension = SuspendedUser.objects.create(
                    user_id_id=reported_user_id,  # FK, so use `_id`
                    sus_start=timezone.now(),
                    sus_end=timezone.now() + timedelta(days=30)  # Customize suspension duration
                )
                suspension.save()


    class Meta:
        db_table = 'report'

@receiver(post_save, sender=Report)
def trigger_suspension(sender, instance, **kwargs):
    if instance.report_status == 'APPROVED':
        instance.check_suspension()

class SuspendedUser(models.Model):
    sus_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE)  # FK to user
    sus_start = models.DateTimeField(auto_now_add=True)
    sus_end = models.DateTimeField()

    def __str__(self):
        return f"User {self.user_id} is suspended from {self.sus_start} to {self.sus_end}"

class ListingApplication(models.Model):
    list_app_id = models.AutoField(primary_key=True)  # Auto-incrementing primary key
    list_app_status = models.CharField(max_length=20, default='PENDING')  # E.g., Approved, Pending, Declined
    list_app_date = models.DateTimeField(default=timezone.now)  # Date of application
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, db_column='list_id')  # Foreign key to Listing
    list_app_reviewer_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, blank=True, null=True, db_column='user_app_reviewer_id', related_name='listing_reviews')  # Add related_name
    list_reason = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = 'listing_application'

        
class Wallet(models.Model):    
    user_id = models.OneToOneField(UserAccount, primary_key=True, editable=False, on_delete=models.PROTECT, db_column='user_id')
    wall_amnt = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    def __str__(self):
        return f"User {self.user_id} wallet: {self.wall_amnt} coins"
    
    class Meta:
        db_table = 'wallet'

class PromoteListing(models.Model):
    prom_id = models.BigAutoField(primary_key=True, editable=False)
    prom_start = models.DateTimeField()
    prom_end = models.DateTimeField()
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, null=False, db_column='list_id')

    class Meta:
        db_table = 'promote_listing'

class Offer(models.Model):
    offer_id = models.BigAutoField(primary_key=True, editable=False)
    offer_price = models.DecimalField(max_digits=12, decimal_places=2, null=True)
    offer_status = models.CharField(max_length=15, default='PENDING')
    offer_created_at = models.DateTimeField(auto_now_add=True, null=True)
    offer_updated_at = models.DateTimeField(auto_now=True, null=True)
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, null=True, db_column='list_id', related_name='offer')
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, null=True, db_column='user_id', related_name='offer')

    class Meta:
        db_table = 'offer'

    def __str__(self):
        return f'User {self.user_id.email} offers {self.offer_price} for list item {self.list_id}'

class ChatRoom(models.Model):
    chatroom_id = models.BigAutoField(primary_key=True, editable=False,)
    chatroom_last_message = models.TextField(null=True, blank=True)
    chatroom_user_1 = models.ForeignKey(UserAccount, on_delete=models.PROTECT, null=True, related_name='user_id_1', db_column='chatroom_user_1')
    chatroom_user_2 = models.ForeignKey(UserAccount, on_delete=models.PROTECT, null=True, related_name='user_id_2', db_column='chatroom_user_2')
    
    class Meta:
        db_table = 'chat_room'
        constraints = [
            models.UniqueConstraint(fields=['chatroom_user_1', 'chatroom_user_2'], name='unique_chat_room'),
        ]
        
    def __str__(self):
        return f'Chat room {self.chatroom_id}'

class ChatMessage(models.Model):
    chatmess_id = models.BigAutoField(primary_key=True, editable=False)
    chatmess_content = models.JSONField(null=True, blank=True) # charfield for now
    chatmess_created_at = models.DateTimeField(auto_now_add=True)
    chatmess_is_read = models.BooleanField(default=False)
    sender_id = models.ForeignKey(UserAccount, on_delete=models.PROTECT, null=True, related_name='messages', db_column='user_id')
    chatroom_id = models.ForeignKey(ChatRoom, on_delete=models.PROTECT, null=False, related_name='messages', db_column='chatroom_id')

    class Meta:
        db_table = 'chat_message'

    def __str__(self):
        return f'Message from {self.sender_id} to room {self.chatroom_id} at {self.chatmess_created_at}'

class Favorite(models.Model):
    fav_id = models.BigAutoField(primary_key=True, editable=False)  # Primary key
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, db_column='list_id')  # Link to Listing
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, db_column='user_id')  # Link to UserAccount
    fav_date = models.DateTimeField(auto_now_add=True)  # Automatically set when a favorite is added

    class Meta:
        db_table = 'favorite'
        unique_together = ('list_id', 'user_id')  # Ensure each user can favorite a listing only once

    def __str__(self):
        return f'Favorite: {self.user_id.email} favorited {self.list_id.list_content}'

class PasswordResetToken(models.Model):
    user = models.OneToOneField(UserAccount, unique=True, on_delete=models.CASCADE, db_column='user_id', related_name='reset_password')
    reset_token = models.TextField(null=True, blank=True)
    reset_token_created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    reset_token_expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'password_reset_token'


class Follow(models.Model):
    follower_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='following_assumptors', db_column='assumee_user_id', limit_choices_to={'is_assumee': True})
    following_id = models.ForeignKey(UserAccount,on_delete=models.CASCADE,related_name='followers_assumees',db_column='assumptor_user_id',limit_choices_to={'is_assumptor': True})
    
    class Meta:
        db_table = 'follow'
        unique_together = ('follower_id', 'following_id')  

    def __str__(self):
        return f"{self.follower_id.email} follows {self.following_id.email}"
    
class Paypal(models.Model):
    user_id = models.OneToOneField(UserAccount, on_delete=models.CASCADE, null=False, primary_key=True, editable=False, db_column='user_id', related_name='paypal')
    paypal_merchant_id = models.CharField(max_length=255, unique=True)
    paypal_linked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table='user_paypal'

class Transaction(models.Model):
    user_id = models.ForeignKey(UserAccount, null=True, blank=True, on_delete=models.SET_NULL, related_name='transactions', db_column='user_id')
    order_id = models.CharField(max_length=255, null=True, blank=True)
    capture_id = models.CharField(max_length=255, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_status = models.CharField(max_length=50)
    transaction_date = models.DateTimeField(auto_now_add=True)
    
    # New category field
    category = models.CharField(max_length=50, default='TOPUP')
    
    class Meta:
        db_table = 'transaction'
    
    def __str__(self):
        return f"Transaction {self.order_id or 'N/A'} - {self.transaction_status}"