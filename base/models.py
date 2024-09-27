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
        return f"Verification for {self.user_id.email}"
    
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
    list_id = models.BigAutoField(primary_key=True, editable=False)
    list_price = models.DecimalField(max_digits=9, decimal_places=2, null=False)
    assumptor_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, null=False, db_column='assumptor_id')

    class Meta:
        db_table = 'listing'

class Offer(models.Model):
    offer_id = models.BigAutoField(primary_key=True, editable=False)
    offer_price = models.DecimalField(max_digits=9, decimal_places=2, null=False)
    assumee_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, null=False, db_column='assumee_id')

    class Meta:
        db_table = 'offer'

class Message(models.Model):
    mess_id = models.BigAutoField(primary_key=True, editable=False)
    mess_content = models.CharField(max_length=255, null=False)
    receiver_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, null=False, db_column='receiver_id', related_name='receiver_id')
    sender_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, null=False, db_column='sender_id', related_name='sender_id')
    mess_date = models.DateTimeField(auto_now_add=True)
    mess_is_read = models.BooleanField(default=False)

    class Meta:
        db_table = 'message'

    def __str__(self):
        return f'Message from {self.sender_id} to {self.receiver_id} at {self.mess_date}'

# class 


