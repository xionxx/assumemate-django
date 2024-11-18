from django.urls import path, include
from django.conf import settings  
from django.conf.urls.static import static 
from rest_framework.routers import DefaultRouter
from . import views

urlpatterns = [
    path('', views.base, name='base'),
    path('register/user/<str:user_type>/', views.upperuser_register, name='upperuser_register'),
    path('account/admin/create/', views.admin_acc_create, name='admin_acc_create'),
    path('list/reviewer/', views.reviewer_acc_list, name='reviewer_acc_list'),
    path('account/reviewer/create/', views.reviewer_acc_create, name='reviewer_acc_create'),
    path('user/edit/profile/', views.edit_profile, name='edit_profile'),
    path('update/profile/', views.update_profile, name='update_profile'),
    path('change/password/', views.change_password, name='change_password'),

    path('activate/<int:admin_id>/', views.usertype_is_active, {'status': True}, name='is_activate'),
    path('deactivate/<int:admin_id>/', views.usertype_is_active, {'status': False}, name='is_deactivate'),

    path('users/application', views.user_application_list, name='user_application_list'),

    path('user_login/', views.user_login, name='user_login'),
    path('logout/', views.logout_user, name='user_logout'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('forgot-password/send-link/', views.send_reset_link, name='send-reset-link'),
    path('reset-password/', views.reset_password_page, name='reset-password-page'),
    path('reset-password/update/', views.reset_password, name='reset-password'),
    path('reset-password/done/', views.reset_pass_done, name='reset-password-done'),

    path('user/onboarded/', views.paypal_return_link, name='onboard_success'),
    # path('', views.paypal_return_link, name='onboard_success'),

     #jericho
    path("Assumemate/Reviewer/Pending Listing/", views.assumemate_rev_pending_list, name="assumemate_rev_pending_list"),
    path("Assumemate/Reviewer/Pending Users/", views.pending_accounts_view, name="pending_accounts_view"),
    path("Assumemate/Reviewer/Reported Users/", views.assumemate_rev_report_users, name="assumemate_rev_report_users"),
    path('Reviewer/View/<int:user_id>/', views.user_detail_view, name='user_detail_view'),
    path('Reviewer/ViewList/<int:list_app_id>/', views.listing_detail_view, name='listing_detail_view'),
    path('acceptlist/<int:list_app_id>/', views.accept_listing, name='accept_listing'),
    path('rejectlist/<int:list_app_id>/', views.reject_listing, name='reject_listing'),
    path('accept/<int:user_id>/', views.accept_user, name='accept_user'),
    path('reject/<int:user_id>/', views.reject_user, name='reject_user'),
    path('acceptreport/<int:report_id>/', views.accept_report, name='accept_report'),
    path('rejectreport/<int:report_id>/', views.reject_report, name='reject_report'),
    path('Reviewer/ViewReport/<int:report_id>/', views.report_detail_view, name='report_detail_view'),
    path('Admin/PlatformReport/', views.platform_report, name='platform_report'),

    #JOSELITO
    path("list/admin/", views.admin_acc_list, name="admin_acc_list"),
    path('assumemate/users/list', views.assumemate_users, name='assumemate_users_list'),
    path('users/details/<int:user_id>/', views.users_view_details, name='users_view_details'),
    path('assumemate/listing/', views.assumemate_listing, name='assumemate_listing'),
    path('listing/details/<int:user_id>/<uuid:list_id>/', views.listing_view_details, name='listing_view_details'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin_details/<int:admin_id>/', views.admin_details, name='admin_details'),
    path('reviewer_details/<int:reviewer_id>/', views.reviewer_details, name='reviewer_details'),
    path('admin?activate/<int:user_id>/', views.toggle_user_status, {'user_type': 'admin?', 'status': True}, name='admin_activate'),
    path('admin?/deactivate/<int:user_id>/', views.toggle_user_status, {'user_type': 'admin?', 'status': False}, name='admin_deactivate'),
    path('reviewers?/activate/<int:user_id>/', views.toggle_user_status, {'user_type': 'reviewer', 'status': True}, name='reviewer_activate'),
    path('reviewers?/deactivate/<int:user_id>/', views.toggle_user_status, {'user_type': 'reviewer', 'status': False}, name='reviewer_deactivate'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)                    

# {
# 'email': 'kangpatricia96@gmail.com',
# 'password': 'tokunoyushi2004'
# }