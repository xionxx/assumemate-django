#trial
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from base.models import SuspendedUser, UserAccount


#command : python manage.py suspend_user
#UPDATE base_suspendeduser SET sus_end = sus_start + INTERVAL '1 minutes';

class Command(BaseCommand):
    help = 'Suspend a user and set their account to inactive'

    def handle(self, *args, **kwargs):
        # User ID to suspend (Replace with actual user ID)
        user_to_suspend = 36

        # Create suspension record for the user
        suspension = SuspendedUser.objects.create(
            user_id_id=user_to_suspend,
            sus_start=timezone.now(),
            sus_end=timezone.now() + timedelta(days=30)
        )

        # Set the user's account status to inactive
        user_account = UserAccount.objects.get(id=user_to_suspend)
        user_account.is_active = False
        user_account.save()

        # Print confirmation
        self.stdout.write(self.style.SUCCESS(f"User {user_to_suspend} suspended and account status set to inactive."))