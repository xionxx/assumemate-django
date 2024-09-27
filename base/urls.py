from django.urls import path, include
from django.conf import settings  
from django.conf.urls.static import static 
from rest_framework.routers import DefaultRouter
from . import views

urlpatterns = [
    path("", views.base, name="base"),
    path("register/user/<str:user_type>", views.upperuser_register, name="upperuser_register"),
    path("account/admin/create", views.admin_acc_create, name="admin_acc_create"),
    path("list/admin", views.admin_acc_list, name="admin_acc_list"),
    path("list/reviewer", views.reviewer_acc_list, name="reviewer_acc_list"),
    path("account/reviewer/create", views.reviewer_acc_create, name="reviewer_acc_create"),

    path("users/application", views.user_application_list, name="user_application_list"),
    path("users/application/approve", views.approve_user, name="approve_user"),
    path("users/application/reject", views.reject_user, name="reject_user"),

    path("login/", views.user_login, name="user_login"),
    path("logout/", views.logout, name="user_logout"),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)                    

# {
# "email": "kangpatricia96@gmail.com",
# "password": "tokunoyushi2004"
# }

