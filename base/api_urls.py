from django.urls import path, include
from django.conf import settings  
from django.conf.urls.static import static 
from rest_framework.routers import DefaultRouter
from . import api_views
from .api_views import MyTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('user-register/', api_views.UserRegister.as_view(), name='user-register'),
    path('login/', api_views.UserLogin.as_view(), name='login'),
    path('logout/', api_views.UserLogout.as_view(), name='logout'),
    path('create-profile/', api_views.UserCreateProfile.as_view(), name='create-profile'),
    path('view-profile/', api_views.GetUserProfile.as_view(), name='view-profile'),
    path('google_login/', api_views.UserGoogleLogin.as_view(), name='google_login'),
    path('token/', MyTokenObtainPairView.as_view(), name='token-obtain-pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('email-verification/', api_views.UserEmailVerification.as_view(), name='email-verification'),
    path('check-user-verification/', api_views.CheckUserVerification.as_view(), name='check-user-verification'),
    path('email-verify/<str:verification_code>/', api_views.VerifyEmail.as_view(), name="email-verify"),
    path('update-profile/', api_views.UpdateUserProfile.as_view(), name="update-profile"),
    path('change-password/', api_views.ChangePasswordAPIView.as_view(), name="change-password"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)                    

# {
# "email": "kangpatricia96@gmail.com",
# "password": "tokunoyushi2004"
# }