import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None):
        """
        Create and return a regular user with an email and password.
        """
        if not email:
            raise ValueError('An Email field must be set')
        if not password:
            raise ValueError('A Password field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        user = self.create_user(email, password)
        user.is_superuser = True
        user.save()

        return user

class UserAccount(AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True, blank=True, null=True)
    is_reviewer = models.BooleanField(default=False)
    is_assumee = models.BooleanField(default=False)
    is_assumptor = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    # auth_provider = models.CharField(max_length=20, default='google')

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.email
    
class UserProfile(models.Model):
    user_prof_id = models.BigAutoField(primary_key=True, editable=False)
    user_prof_fname = models.CharField(max_length=50)
    user_prof_lname = models.CharField(max_length=50)
    user_prof_gender = models.CharField(max_length=6)
    user_prof_dob = models.DateField()
    user_prof_mobile = models.CharField(max_length=11)
    user_prof_address = models.CharField(max_length=255)
    user_prof_pic = models.URLField(null=True, blank=True)
    user_prof_valid_id = models.URLField(null=True, blank=True)
    user_id = models.OneToOneField(UserAccount, null=False, on_delete=models.CASCADE, db_column='user_id', related_name='profile')

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
    user_prof_id = models.OneToOneField(UserProfile, null=False, on_delete=models.CASCADE, db_column='user_prof_id', primary_key=True, editable=False)
    user_app_status = models.CharField(max_length=10, default='PENDING')
    user_app_approved_at = models.DateTimeField(blank=True, null=True)
    user_app_reviewer_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, blank=True, null=True, db_column='user_app_reviewer_id')

    class Meta:
        db_table = 'user_application'

class Listing(models.Model):
    list_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    list_content = models.JSONField(null=True, blank=True)  # JSON data for car details
    list_status = models.CharField(max_length=20, default="active")  # Default status
    list_duration = models.DateTimeField(null=True, blank=True)  # Duration as date & time
    user_id = models.ForeignKey(UserAccount, null=True, blank=True, on_delete=models.PROTECT, db_column='user_id', related_name='listing')

    def __str__(self):
        return str(self.list_id)

    class Meta:
        db_table = 'listing'
        
# class Wallet(models.Model):
#     wall_id = models.BigAutoField(primary_key=True, editable=False)
#     wall_amnt = models.DecimalField(max_digits=10, decimal_places=2)

#     def __str__(self):
#         return f"Wallet {self.wall_id}: {self.wall_amnt} coins"

class Offer(models.Model):
    offer_id = models.BigAutoField(primary_key=True, editable=False)
    offer_price = models.DecimalField(max_digits=10, decimal_places=2, null=True)
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
    chatmess_content = models.TextField(null=True, blank=True) # charfield for now
    chatmess_created_at = models.DateTimeField(auto_now_add=True)
    chatmess_is_read = models.BooleanField(default=False)
    sender_id = models.ForeignKey(UserAccount, on_delete=models.PROTECT, null=True, related_name='messages', db_column='user_id')
    chatroom_id = models.ForeignKey(ChatRoom, on_delete=models.PROTECT, null=False, related_name='messages', db_column='chatroom_id')

    class Meta:
        db_table = 'chat_message'

    def __str__(self):
        return f'Message from {self.sender_id} to room {self.chatroom_id} at {self.chatmess_created_at}'


