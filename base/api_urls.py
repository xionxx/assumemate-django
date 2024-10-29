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
    path('view/<int:user_id>/profile/', api_views.ViewOtherProfile.as_view(), name='view-other-profile'),
    path('google_login/', api_views.UserGoogleLogin.as_view(), name='google_login'),
    path('token/', MyTokenObtainPairView.as_view(), name='token-obtain-pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('email-verification/', api_views.UserEmailVerification.as_view(), name='email-verification'),
    path('check-user-verification/', api_views.CheckUserVerification.as_view(), name='check-user-verification'),
    path('email-verified/page/', api_views.email_verified, name='user-verified-page'),
    path('email-verify/<str:verification_code>/', api_views.VerifyEmail.as_view(), name='email-verify'),
    # path('find-password/<str:verification_code>/', api_views.reset_password, name='find-password'),
    path('update-profile/', api_views.UpdateUserProfile.as_view(), name='update-profile'),
    path('update-profile/picture/', api_views.UpdateUserProfilePicture.as_view(), name='update-profile-picture'),
    path('change-password/', api_views.ChangePasswordAPIView.as_view(), name='change-password'),
    path('view-convo/<int:chatroom_id>/', api_views.GetMessageAPIView.as_view(), name='view-convo'),
    path('make/offer/', api_views.MakeOfferAPIView.as_view(), name='make-offer'),
    path('update/offer/', api_views.UpdateOfferAPIView.as_view(), name='update-offer'),
    path('view/user/inbox/', api_views.UserChatRoomAPIView.as_view(), name='inbox'),
    path('add/listings/', api_views.CarListingCreate.as_view(), name='car-listing-create'),
    path('listings/details/<uuid:list_id>/', api_views.ListingDetailView.as_view(), name='listing_details'),
    path('get/active/offer/<int:receiver_id>/', api_views.GetActiveOfferAPIView.as_view(), name='active-offer'),
    path('get/<int:receiver_id>/listing/offer/', api_views.GetListingOfferAPIView.as_view(), name='listing-offer'),
    path('wallet/<int:pk>/add-coins/', api_views.AddCoinsToWalletView.as_view(), name='add-coins'),
    path('wallet/total-coins/', api_views.GetTotalCoinsView.as_view(), name='total-coins'),

    path('listings/<str:category>/', api_views.ListingByCategoryView.as_view(), name='listings_by_category'),
    # path('listings/details/<str:list_id>/', api_views.ListingDetailView.as_view(), name='listing_details'),

    path('favorites/add/', api_views.AddFavoriteView.as_view(), name='add_favorite'),
    path('favorites/remove/', api_views.RemoveFavoriteView.as_view(), name='remove_favorite'),
    path('favorites/', api_views.FavoritesView.as_view(), name='favorites'),
    path('favorites/mark', api_views.FavoritesMarkView.as_view(), name='favorites_mark'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)                    

# {
# "email": "kangpatricia96@gmail.com",
# "password": "tokunoyushi2004"
# }