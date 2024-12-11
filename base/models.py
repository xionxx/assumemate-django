from datetime import timedelta, timezone
from django.utils import timezone
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.dispatch import receiver
from base.utils import send_push_notification

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
    fcm_token = models.CharField(max_length=255, blank=True, null=True)
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.email
    
    class Meta:
        db_table = 'user_account'

class UserProfile(models.Model):
    DEFAULT_PROFILE_PIC = 'https://res.cloudinary.com/dbroe2hjh/image/upload/v1733245571/no-profile_xnyyoi.jpg'

    user_prof_fname = models.CharField(max_length=50, null=False, blank=False)
    user_prof_lname = models.CharField(max_length=50, null=False, blank=False)
    user_prof_gender = models.CharField(max_length=6, null=False, blank=False)
    user_prof_dob = models.DateField(null=False, blank=False)
    user_prof_mobile = models.CharField(max_length=13, unique=True)
    user_prof_address = models.CharField(max_length=255)
    user_prof_pic = models.URLField(default=DEFAULT_PROFILE_PIC)
    user_prof_valid_pic = models.URLField(default=DEFAULT_PROFILE_PIC)
    user_prof_valid_id = models.URLField(null=False, blank=False)
    user_id = models.OneToOneField(UserAccount, null=False, primary_key=True, editable=False, on_delete=models.CASCADE, db_column='user_id', related_name='profile')

    def __str__(self):
        return f"{self.user_prof_fname} {self.user_prof_lname}"

    class Meta:
        db_table = 'user_profile'
        constraints = [
            # models.UniqueConstraint(fields=['user_prof_fname', 'user_prof_lname', 'user_prof_dob'], name='unique_user'),
        ]

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
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ]

    user_id = models.OneToOneField(UserAccount, null=False, on_delete=models.CASCADE, db_column='user_id', related_name='user_application', primary_key=True, editable=False)
    user_app_status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    user_app_approved_at = models.DateTimeField(blank=True, null=True)
    user_app_reviewer_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, blank=True, null=True, db_column='user_app_reviewer_id')
    user_app_declined_at = models.DateTimeField(default=timezone.now)
    user_reason = models.CharField(max_length=255, null=True)
    class Meta:
        db_table = 'user_application'

class Listing(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('ACTIVE', 'Active'),
        ('RESERVED', 'Reserved'),
        ('SOLD', 'Sold'),
        ('ARCHIVED', 'Archived'),
    ]

    list_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    list_content = models.JSONField(null=True, blank=True)
    list_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    list_duration = models.DateTimeField(null=True, blank=True) 
    user_id = models.ForeignKey(UserAccount, null=False, blank=False, on_delete=models.PROTECT, db_column='user_id', related_name='listing')

    def __str__(self):
        return str(self.list_id)

    class Meta:
        db_table = 'listing'

class Report(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ]

    report_id = models.AutoField(primary_key=True)
    report_details = models.JSONField(null=True)
    reviewer = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='reviewed_reports', db_column='user_id', null=True)
    updated_at = models.DateTimeField(default=timezone.now)
    report_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')  # Approved, Pending, Declined
    report_reason = models.JSONField(null=True)

    def save(self, *args, **kwargs):
        # Check if the status is being updated
        if self.pk:
            old_status = Report.objects.filter(pk=self.pk).values_list('report_status', flat=True).first()
            if old_status != self.report_status:  # Status changed
                self.handle_notifications()

        super().save(*args, **kwargs)

    def handle_notifications(self):
        """Handles notifications and sends FCM push notifications based on the report status."""
        reported_user_id = self.report_details.get('reported_user_id')
        reporter_id = self.report_details.get('reporter_id')

        # Ensure IDs are available
        if not reported_user_id or not reporter_id:
            return

        # Fetch user accounts
        reported_user = UserAccount.objects.filter(id=reported_user_id).first()
        reporter_user = UserAccount.objects.filter(id=reporter_id).first()

        if self.report_status == 'APPROVED':
            # Notify the reported user
            if reported_user:
                Notification.objects.create(
                    notif_message='Warning: You have been reported by a user.',
                    recipient=reported_user,
                    triggered_by=reporter_user,  # Reporter is the trigger
                    notification_type="Report",
                )
                # Send FCM notification to the reported user
                fcm_token = reported_user.fcm_token
                if fcm_token:
                    send_push_notification(
                        fcm_token=fcm_token,
                        title="Warning",
                        body="You have been reported by a user.",
                        data_payload={"route": "reports/sent/"},
                    )

            # Notify the reporter
            if reporter_user:
                Notification.objects.create(
                    notif_message='Your report has been approved.',
                    recipient=reporter_user,
                    triggered_by=reporter_user,  # Self-triggered
                    notification_type="Report",
                )
                # Send FCM notification to the reporter
                fcm_token = reporter_user.fcm_token
                if fcm_token:
                    send_push_notification(
                        fcm_token=fcm_token,
                        title="Report approved",
                        body="Your report has been approved.",
                        data_payload={"route": "reports/sent/"},
                    )

        elif self.report_status == 'REJECTED':
            # Notify the reporter
            if reporter_user:
                Notification.objects.create(
                    notif_message='Your report has been rejected.',
                    recipient=reporter_user,
                    triggered_by=reporter_user,  # Self-triggered
                    notification_type="Report",
                )
                # Send FCM notification to the reporter
                fcm_token = reporter_user.fcm_token
                if fcm_token:
                    send_push_notification(
                        fcm_token=fcm_token,
                        title="Report Rejected",
                        body="Your report has been rejected.",
                        data_payload={"route": "reports/sent/"},
                    )

    def check_suspension(self):
        """Check if a user should be suspended based on approved reports."""
        reported_user_id = self.report_details.get('reported_user_id')
        reporter_id = self.report_details.get('reporter_id')
        if not reported_user_id:
            return
        approved_reports = Report.objects.filter(
            report_details__reported_user_id=reported_user_id,
            report_status='APPROVED'
        ).exclude(report_details__reporter_id=reporter_id).count()

        if approved_reports >= 3: 
            if not SuspendedUser.objects.filter(user_id=reported_user_id).exists():
                suspension = SuspendedUser.objects.create(
                    user_id_id=reported_user_id,  
                    sus_start=timezone.now(),
                    sus_end=timezone.now() + timedelta(days=30)
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

    def save(self, *args, **kwargs):
        """Custom save method to set sus_end to 20 years if user_id >= 3."""
        # Check if user_id is greater than or equal to 3
        if self.user_id.id >= 3:
            self.sus_end = timezone.now() + timedelta(days=20 * 365)  # 20 years
        super().save(*args, **kwargs)  # Save the instance


        user = self.user_id  
        user.is_active = False  
        user.save() 

    def is_active(self):
            """Check if the suspension is still active."""
            if self.sus_end <= timezone.now():
                # If the suspension has expired, lift it (delete the record)
                self.delete()
                return False  # Return False because the suspension has ended
            return True
    
    def __str__(self):
        return f"User {self.user_id} is suspended from {self.sus_start} to {self.sus_end}"


class ListingApplication(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ]

    list_app_id = models.AutoField(primary_key=True) 
    list_app_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default ='PENDING') 
    list_app_date = models.DateTimeField(default=timezone.now)  
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, db_column='list_id')  
    list_app_reviewer_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, blank=True, null=True, db_column='user_app_reviewer_id', related_name='listing_reviews')  # Add relate
    list_reason = models.CharField(max_length=255, null=True)

    def save(self, *args, **kwargs):
        status_changed = False
        if self.pk:  # If instance already exists in the database
            original = ListingApplication.objects.get(pk=self.pk)
            if original.list_app_status != self.list_app_status:
                status_changed = True

        super().save(*args, **kwargs)

        if (status_changed or self._state.adding) and self.list_app_status in ['APPROVED', 'REJECTED']:
            message = f"Your listing application {self.list_app_id} has been {self.list_app_status.lower()}."
            Notification.objects.create(
                notif_message=message,
                recipient=self.list_id.user_id,  # Owner of the listing
                triggered_by=self.list_app_reviewer_id,  # Reviewer who changed the status
                notification_type="Listing",
                list_id=self.list_id  # Link to the listing
            )
            print("Notification created successfully!")

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
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('ACCEPTED', 'Accepted'),
        ('PAID', 'Paid'),
        ('REJECTED', 'Rejected'),
        ('CANCELLED', 'Cancelled'),
    ]

    offer_id = models.BigAutoField(primary_key=True, editable=False)
    offer_price = models.DecimalField(max_digits=12, decimal_places=2, null=False)
    offer_status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='PENDING')
    offer_created_at = models.DateTimeField(auto_now_add=True)
    offer_updated_at = models.DateTimeField(auto_now=True)
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, db_column='list_id', related_name='offer')
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, db_column='user_id', related_name='offer')

    class Meta:
        db_table = 'offer'

    def __str__(self):
        return f'User {self.user_id.email} offers {self.offer_price} for list item {self.list_id}'

    def save(self, *args, **kwargs):
        is_new = self._state.adding  
        old_status = None

        if not is_new:

            old_instance = Offer.objects.filter(pk=self.pk).first()
            if old_instance:
                old_status = old_instance.offer_status

        super().save(*args, **kwargs)  

        if is_new:

            self.create_offer()
        elif old_status and old_status != self.offer_status:

            print(old_status)
            print('tangina')
            print(self.offer_status)

            self.update_offer_status(self.offer_status)

    def create_offer(self):
        try:

            list_owner = self.list_id.user_id
            offer_message = f"New offer of {self.offer_price} for your listing."
            print(f"Notification message prepared: {offer_message}")
            print(f"Recipient: {list_owner.email}")


            
            fcm_token = self.list_id.user_id.fcm_token
            if fcm_token:

                user_profile = self.user_id.profile  # This will access the related UserProfile object

                offer_message = f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} has made an offer of {self.offer_price} for your listing."
                route = f"ws/chat/{self.user_id.id}/$"  
                print(f"Debug: Sending follow push notification with route: {route}")

                data_payload={
                        "route": route,  
                        "userId": str(self.user_id.id)  
                    }
                
                send_push_notification(
                    fcm_token=fcm_token,
                    title="New Offer",
                    body=offer_message,
                    data_payload=data_payload
                    
                )
                print(f"Debug: Push notification payload: {{'fcm_token': '{fcm_token}', 'title': 'New Offer', 'body': '{offer_message}', 'data': {data_payload}}}")
                
                print("Debug: Follow push notification sent successfully.")
            else:
                print("Debug: No FCM token found for the user.")
            
            # Create a notification object
            notification = Notification.objects.create(
                notif_message=offer_message,
                recipient=list_owner,
                list_id=self.list_id,
                triggered_by=self.user_id,
                notification_type='offer',
            )

            
            print(f"Notification created successfully: {notification}")

        except Exception as e:
            print(f"Error creating offer or notification: {e}")
            raise


    def update_offer_status(self, new_status):
        try:
            if new_status == "CANCELLED" or new_status == "PAID":
                offer_status_message = f"The offer of {self.offer_price} for the listing has been {new_status.lower()}."
                Notification.objects.create(
                    notif_message=offer_status_message,
                    recipient=self.list_id.user_id,
                    list_id=self.list_id,
                    triggered_by=self.user_id,
                    notification_type='offer',
                )
                if new_status == "CANCELLED": #if si assumee mu cancel (to assumptor)
                    fcm_token = self.list_id.user_id.fcm_token  
                    if fcm_token:
                        user_profile = self.user_id.profile 
                        new_title = 'Cancelled Offer'
                        offer_message = (
                        f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} "
                        f"has {new_status.lower()} his offer ₱ {self.offer_price} for the listing."  
                    )
                if new_status == "PAID" : #if si ASSUMEE mu bayad (to assumptor)
                    fcm_token = self.list_id.user_id.fcm_token  
                    if fcm_token:
                        user_profile = self.list_id.user_id.profile 
                        new_title = 'Paid Offer'
                        offer_message = (
                        f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} "
                        f"has {new_status.lower()} your offer ₱ {self.offer_price} for the listing."
                    )

            if new_status == "REJECTED" or new_status =="ACCEPTED":
                offer_status_message = f"Your offer of {self.offer_price} for the listing has been {new_status.lower()}."
                Notification.objects.create(
                    notif_message=offer_status_message,
                    recipient=self.user_id,
                    list_id=self.list_id,
                    triggered_by=self.list_id.user_id,
                    notification_type='offer',
                )
                if new_status == "REJECTED" : #if si ASSUMPTOR MUCANCEL/ACCEPTED (to assumee)
                    fcm_token = self.user_id.fcm_token  
                    if fcm_token:
                        user_profile = self.user_id.profile 
                        new_title = 'Rejected Offer'
                        offer_message = (
                        f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} "
                        f"has {new_status.lower()} your offer ₱ {self.offer_price} for the listing."
                    )
                        
                if new_status =="ACCEPTED": #if si ASSUMPTOR ACCEPTED (to assumee)
                    fcm_token = self.user_id.fcm_token  
                    if fcm_token:
                        user_profile = self.user_id.profile 
                        new_title = 'Accepted Offer'
                        offer_message = (
                        f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} "
                        f"has {new_status.lower()} your offer ₱ {self.offer_price} for the listing."
                    )

                    
            if fcm_token:
                if new_status == "CANCELLED" or new_status == "PAID":
                    route = f"ws/chat/{user_profile.user_id.id}/$"
                    print(f"Debug: Sending follow push notification with route: {route}")

                    data_payload = {
                        "route": route,
                        "userId": str(user_profile.user_id.id),
                    }
                else:
                    route = f"ws/chat/{self.list_id.user_id}/$"
                    print(f"Debug: Sending follow push notification with route: {route}")

                    data_payload = {
                        "route": route,
                        "userId": str(self.list_id.user_id.id),
                    }


                send_push_notification(
                    fcm_token=fcm_token,
                    title=new_title,
                    body=offer_message,
                    data_payload=data_payload,
                )

            print(f"Offer status notification sent: {offer_status_message}")
        except Exception as e:
            print(f"Error updating offer status: {e}")

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
    chatmess_content = models.JSONField(null=False, blank=False) # charfield for now
    chatmess_created_at = models.DateTimeField(auto_now_add=True)
    chatmess_is_read = models.BooleanField(default=False)
    sender_id = models.ForeignKey(UserAccount, on_delete=models.PROTECT, null=False, related_name='messages', db_column='user_id')
    chatroom_id = models.ForeignKey(ChatRoom, on_delete=models.PROTECT, null=False, related_name='messages', db_column='chatroom_id')

    class Meta:
        db_table = 'chat_message'

    def __str__(self):
        return f'Message from {self.sender_id} to room {self.chatroom_id} at {self.chatmess_created_at}'

class Follow(models.Model):
    follower_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='following', db_column='follower_id')
    following_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='follower',db_column='following_id')

    class Meta:

        db_table = 'follow'
        unique_together = ('follower_id', 'following_id') 

    def __str__(self):
        return f"{self.follower_id.email} follows {self.following_id.email}"

    def save(self, *args, **kwargs):
        is_new_instance = self._state.adding
        was_existing_instance = not is_new_instance

        # Save the Follow instance
        super().save(*args, **kwargs)

        if is_new_instance:

            user_profile = self.follower_id.profile
            # Send notification when a user follows another user
            notification = Notification.objects.create(
                notif_message=f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} has started following you.",
                recipient=self.following_id,
                triggered_by=self.follower_id,
                notification_type="follow",
                follow_id=self  # Link to the follow instance
            )
            self._send_follow_push_notification()

        elif was_existing_instance:
            # Handle unfollow scenario: if the record was deleted (unfollowed)
            # You may need to add logic for deletion detection, e.g. `delete` flag.
            pass

    def _send_follow_push_notification(self):
        """Send a push notification when the user is followed."""
        try:
            fcm_token = self.following_id.fcm_token  
            if fcm_token:
                user_profile = self.follower_id.profile
                route = f"view/{self.follower_id.id}/profile"
                print("Debug: Sending follow push notification...")
                send_push_notification(
                    fcm_token=fcm_token,
                    title="New Follower",
                    body=f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} has started following you.",
                    data_payload={
                        "route": route,
                        "userId": str(self.follower_id.id)
                    }
                )
                print("Debug: Follow push notification sent successfully.")
            else:
                print("Debug: No FCM token found for the user.")
        except Exception as e:
            print(f"Error: Failed to send follow push notification. {e}")

    def create_or_update_notification(self, delete=False):
        """Create or update a notification for follows."""
        try:
            notification = Notification.objects.get(
                recipient=self.following_id,
                notification_type="follow",
                follow_id=self
            )

            if delete:
                # If unfollowing, delete the notification
                notification.delete()
                print("Debug: Deleted follow notification because the user unfollowed.")
                return
            else:
                # Update the notification message or handle other changes
                notification.notif_message = f"{self.follower_id.email} has started following you."
                notification.save()
                print("Debug: Updated follow notification.")

        except Notification.DoesNotExist:
            if not delete:
                # Create a new notification if it doesn't exist
                notification = Notification.objects.create(
                    notif_message=f"{self.follower_id.email} has started following you.",
                    recipient=self.following_id,
                    triggered_by=self.follower_id,
                    notification_type="follow",
                    follow_id=self
                )
                print("Debug: Created new follow notification.")

class Favorite(models.Model):
    fav_id = models.BigAutoField(primary_key=True, editable=False)  
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, db_column='list_id')  
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, db_column='user_id')  
    fav_date = models.DateTimeField(auto_now_add=True)  

    def save(self, *args, **kwargs):
        is_new_instance = not self.pk

        super(Favorite, self).save(*args, **kwargs)  

        if is_new_instance and self.user_id != self.list_id.user_id:
            like_log = LikeLog.objects.create(list_id=self.list_id, user_id=self.user_id)
            like_log.create_or_update_notification(delete=False)

    def delete(self, *args, **kwargs):
        try:

            like_log = LikeLog.objects.get(
                list_id=self.list_id, 
                user_id=self.user_id  
            )
            like_log.delete()

            like_log.create_or_update_notification(delete=True)

        except LikeLog.DoesNotExist:
            pass  

        super(Favorite, self).delete(*args, **kwargs)

    class Meta:
        db_table = 'favorite'
        unique_together = ('list_id', 'user_id')  

    def __str__(self):
        return f'Favorite: {self.user_id.email} favorited {self.list_id.list_content}'

class PasswordResetToken(models.Model):
    user = models.OneToOneField(UserAccount, unique=True, on_delete=models.CASCADE, db_column='user_id', related_name='reset_password')
    reset_token = models.TextField(null=True, blank=True)
    reset_token_created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    reset_token_expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'password_reset_token'

class LikeLog(models.Model):
    log_id = models.BigAutoField(primary_key=True, editable=False) 
    list_id = models.ForeignKey(Listing, on_delete=models.CASCADE, db_column='list_id') 
    user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, db_column='user_id') 
    log_date = models.DateTimeField(auto_now_add=True)  

    class Meta:
        db_table = 'like_log'
        unique_together = ('list_id', 'user_id') 

    def __str__(self):
        return f'LikeLog: {self.user_id.email} liked {self.list_id.list_content["title"]}'

    def create_or_update_notification(self, delete=False):
        """
        Create or update a notification when a user likes or unlikes a listing, 
        and send an updated push notification with the current like count.
        """
        # Count total likes for the listing
        total_likes = LikeLog.objects.filter(list_id=self.list_id).count()
        user_profile = self.user_id.profile
        # Create the notification message based on total likes
        if total_likes == 1:
            message = f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} liked your listing."
        elif total_likes > 1:
            message = f"{user_profile.user_prof_fname} {user_profile.user_prof_lname} and {total_likes - 1} others liked your listing."
        else:
            message = ""  # No message needed if no likes remain

        try:
            # Try to retrieve an existing notification for this listing and user
            notification = Notification.objects.get(
                recipient=self.list_id.user_id,
                list_id=self.list_id,
                notification_type="Listing"
            )

            if delete:
                # If deleting, handle removal of the notification if it is the last like
                if total_likes == 0:
                    notification.delete()
                    send_push = False
                    print("Debug: Deleted notification, as it was the last like.") 
                else:
                    # Update the notification with the new like count
                    notification.notif_message = message
                    notification.save()
                    send_push = False  # Don't send push notification for unlikes
                    print(f"Debug: Updated notification message to '{message}', but no push notification sent.")  

            else:
                # Update the notification message for likes
                notification.notif_message = message
                notification.save()
                send_push = True
                print(f"Debug: Updated notification message to '{message}'.")  

        except Notification.DoesNotExist:
            # Create a new notification if it doesn't exist and not in delete mode
            if not delete and total_likes > 0:
                notification = Notification.objects.create(
                    notif_message=message,
                    recipient=self.list_id.user_id,
                    list_id=self.list_id,
                    triggered_by=self.user_id,
                    notification_type="like"
                )
                send_push = True
                print("Debug: Created new notification.") 
            else:
                send_push = False

        # Retrieve the FCM token of the listing's user
        try:
            fcm_token = self.list_id.user_id.fcm_token
            print(f"Debug: Retrieved fcm_token = {fcm_token}") 
        except AttributeError as e:
            print(f"Error: Failed to retrieve fcm_token. {e}")  
            fcm_token = None

        # Send push notification only if conditions are met
        if send_push and fcm_token:
            print("Debug: Sending push notification...") 
            route = f"/listings/details/"
            try:
                send_push_notification(
                    fcm_token=fcm_token,
                    title="New Like on Your Listing",
                    body=message,
                    data_payload={
                        "route": route,
                        "listingId": str(self.list_id),
                        "userId": str(self.list_id.user_id.id)
                    },
                )
                print("Debug: Push notification sent successfully.")  
            except Exception as e:
                print(f"Error: Failed to send push notification. {e}")
        else:
            if not send_push:
                print("Debug: send_push is False, notification not sent.")  
            elif not fcm_token:
                print("Debug: fcm_token is missing, notification not sent.") 


class Notification(models.Model):
    notif_id = models.BigAutoField(primary_key=True, editable=False)  # Primary key
    notif_message = models.CharField(max_length=255)  # Notification message
    notif_created_at = models.DateTimeField(auto_now_add=True)  # Creation timestamp
    notif_is_read = models.BooleanField(default=False)  # Read status

    # Link to User who receives the notification
    recipient = models.ForeignKey(
        UserAccount,
        on_delete=models.CASCADE,
        related_name='notifications',
        db_column='recipient_id'
    )

    # Optional link to a Listing, if the notification relates to a specific listing
    list_id = models.ForeignKey(
        Listing,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        db_column='list_id'
    )

    # ForeignKey to the user who triggered the notification (e.g., Assumee who favorited a listing)
    triggered_by = models.ForeignKey(
        UserAccount,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='triggered_notifications',
        db_column='triggered_by_id'
    )
    notification_type = models.CharField(max_length=50, default="general")  # e.g., "follow" or "general"
    follow_id = models.ForeignKey('follow', null=True, blank=True, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'notification'
        ordering = ['-notif_created_at']  # Order notifications by the most recent first

    def __str__(self):
        return f"Notification for {self.recipient.email}: {self.notif_message}"

class Paypal(models.Model):
    user_id = models.OneToOneField(UserAccount, on_delete=models.CASCADE, null=False, primary_key=True, editable=False, db_column='user_id', related_name='paypal')
    paypal_merchant_id = models.CharField(max_length=255, unique=True)
    paypal_linked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table='user_paypal'

class ReservationInvoice(models.Model):
    order_id= models.BigAutoField(primary_key=True, editable=False, null=False, db_column='invoice_id')
    order_price = models.DecimalField(max_digits=12, decimal_places=2, db_column='invoice_price')
    order_status = models.CharField(max_length=255, default='PENDING', db_column='invoice_status')
    order_created_at = models.DateTimeField(auto_now_add=True,db_column='invoice_created_at')
    order_updated_at = models.DateTimeField(auto_now=True, db_column='invoice_updated_at')
    offer_id = models.ForeignKey(Offer, null=True, on_delete=models.SET_NULL, blank=True, db_column='offer_id')
    list_id = models.ForeignKey(Listing, null=True, on_delete=models.SET_NULL, blank=True, db_column='list_id')
    user_id = models.ForeignKey(UserAccount, blank=False, null=False, on_delete=models.PROTECT, related_name='invoice', db_column='user_id' )

    class Meta:
        db_table = 'invoice'

class Transaction(models.Model):
    transaction_id = models.BigAutoField(primary_key=True, editable=False)
    user_id = models.ForeignKey(UserAccount, null=True, blank=True, on_delete=models.SET_NULL, related_name='transactions', db_column='user_id')
    transaction_paypal_order_id = models.CharField(max_length=255, null=True, blank=True)
    transaction_paypal_capture_id = models.CharField(max_length=255, null=True, blank=True)
    transaction_amount = models.DecimalField(max_digits=12, decimal_places=2)
    # transaction_status = models.CharField(max_length=50, default='COMPLETED')
    transaction_date = models.DateTimeField(auto_now_add=True)
    transaction_type = models.CharField(max_length=50, default='TOPUP')
    order_id=models.ForeignKey(ReservationInvoice, on_delete=models.SET_NULL, null=True, blank=True, db_column='invoice_id', related_name='invoice')
    
    class Meta:
        db_table = 'transaction'
    
    def __str__(self):
        return f"Transaction {self.order_id or 'N/A'} - complete"

class PayoutRequest(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('SENT', 'Approved'),
        ('REJECTED', 'Rejected'),
        # ('CANCELLED', 'Cancelled'),
        ('COMPLETED', 'Completed'),
    ]

    payout_id = models.BigAutoField(primary_key=True, editable=False, null=False, db_column='payout_id')
    payout_paypal_email = models.EmailField(null=False, blank=False)
    payout_status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='PENDING')
    payout_created_at = models.DateTimeField(auto_now_add=True, null=False)
    payout_updated_at = models.DateTimeField(auto_now=True, null=False)
    order_id = models.OneToOneField(ReservationInvoice, blank=False, null=False, on_delete=models.PROTECT, db_column='order_id', related_name='payout_request')
    user_id = models.ForeignKey(UserAccount, blank=False, null=False, on_delete=models.PROTECT, related_name='payout_request', db_column='user_id' )
    
    class Meta:
        db_table = 'payout_request'

class RefundRequest(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('REFUNDED', 'Approved'),
    ]

    refund_id = models.BigAutoField(primary_key=True, editable=False, null=False, db_column='refund_id')
    refund_status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='PENDING')
    paypal_refund_id = models.CharField(max_length=255, null=True, blank=True)
    refund_created_at = models.DateTimeField(auto_now_add=True, null=False)
    refund_updated_at = models.DateTimeField(auto_now=True, null=False)
    order_id = models.OneToOneField(ReservationInvoice, blank=False, null=False, on_delete=models.PROTECT, db_column='order_id', related_name='refund_request')
    user_id = models.ForeignKey(UserAccount, blank=False, null=False, on_delete=models.PROTECT, related_name='refund_request', db_column='user_id' )
    
    class Meta:
        db_table = 'refund_request'

class Rating(models.Model):
    rate_id = models.BigAutoField(primary_key=True, editable=False)
    from_user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='ratings_given', db_column='from_user_id')
    to_user_id = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='ratings_received', db_column='to_user_id')
    rating_value = models.IntegerField(choices=[(1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5')])  # Example 1-5 rating scale
    review_comment = models.TextField(null=True, blank=True)  # Optional comment for the rating
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'rating'
        unique_together = ['from_user_id', 'to_user_id'] 

    def __str__(self):
        return f"Rating from {self.from_user_id.email} to {self.to_user_id.email}: {self.rating_value}"


