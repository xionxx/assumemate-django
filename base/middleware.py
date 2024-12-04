from django.utils import timezone
from base.models import SuspendedUser, UserAccount
from django.db import transaction
from django.db.models import F


class CheckSuspensionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            suspensions = SuspendedUser.objects.filter(user_id=request.user)
            for suspension in suspensions:
                pass
            active_suspension = suspensions.filter(sus_end__gt=timezone.now()).first()

            with transaction.atomic(): 
                try:
                    user = UserAccount.objects.get(pk=request.user.pk)
                except UserAccount.DoesNotExist:
                    return self.get_response(request)
                if active_suspension:
                    user.is_active = False
                    user.save()
                else:
                    user.is_active = True
                    user.save()
                    suspensions.delete()

        return self.get_response(request)

