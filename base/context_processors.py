from .models import UserApplication, Report, ListingApplication

def notification_context(request):
    # Count pending users
    pending_users_count = UserApplication.objects.filter(user_app_status='PENDING').count()

    # Count pending reports
    reports_count = Report.objects.filter(report_status='PENDING').count()

    # Count pending listings
    listings_pending_count = ListingApplication.objects.filter(list_app_status='PENDING').count()

    # Prepare notification details for the dropdown
    notifications = [
        {
            'message': f'{pending_users_count} pending user(s)',
            'url': '/Assumemate/Reviewer/Pending Users'  # Replace with the correct URL
        },
        {
            'message': f'{reports_count} pending report(s)',
            'url': '/Assumemate/Reviewer/Reported Users'  # Replace with the correct URL
        },
        {
            'message': f'{listings_pending_count} pending listing(s)',
            'url': '/Assumemate/Reviewer/Pending Listing'  # Replace with the correct URL
        }
    ]

    total_notifications_count = pending_users_count + reports_count + listings_pending_count

    return {
        'notifications': notifications,
        'total_notifications_count': total_notifications_count
    }