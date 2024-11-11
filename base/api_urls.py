from django.urls import path, include
from django.conf import settings  
from django.conf.urls.static import static 
from rest_framework.routers import DefaultRouter
from . import api_views
from . import paypal_views
from .api_views import MyTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('user-register/', api_views.UserRegister.as_view(), name='user-register'),
    path('login/', api_views.UserLogin.as_view(), name='login'),
    path('token/', MyTokenObtainPairView.as_view(), name='token-obtain-pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('logout/', api_views.UserLogout.as_view(), name='logout'),
    path('create-profile/', api_views.UserCreateProfile.as_view(), name='create-profile'),
    path('view-profile/', api_views.GetUserProfile.as_view(), name='view-profile'),
    path('view/<int:user_id>/profile/', api_views.ViewOtherProfile.as_view(), name='view-other-profile'),
    path('check/user/email/', api_views.CheckGoogleEmail.as_view(), name='check-email'),
    path('email-verification/', api_views.UserEmailVerification.as_view(), name='email-verification'),
    path('check-user-verification/', api_views.CheckUserVerification.as_view(), name='check-user-verification'),
    path('email-verified/page/', api_views.email_verified, name='user-verified-page'),
    path('email-verify/<str:verification_code>/', api_views.VerifyEmail.as_view(), name='email-verify'),
    path('find-password/', api_views.ResetPasswordLink.as_view(), name='find-password'),
    path('update-profile/', api_views.UpdateUserProfile.as_view(), name='update-profile'),
    path('update-profile/picture/', api_views.UpdateUserProfilePicture.as_view(), name='update-profile-picture'),
    path('change-password/', api_views.ChangePasswordAPIView.as_view(), name='change-password'),
    path('view-convo/<int:receiver_id>/', api_views.GetMessageAPIView.as_view(), name='view-convo'),
    path('make/offer/', api_views.MakeOfferAPIView.as_view(), name='make-offer'),
    path('update/offer/', api_views.UpdateOfferAPIView.as_view(), name='update-offer'),
    path('assumptor/list/offers/', api_views.AssumptorListOffers.as_view(), name='assumptor-list-offers'),
    path('assumptor/all/listings/', api_views.AssumptorListings.as_view(), name='assumptor-lists'),
    path('assumptor/<int:user_id>/all/listings/', api_views.AssumptorViewListings.as_view(), name='assumptor-lists'),
    path('view/user/inbox/', api_views.UserChatRoomAPIView.as_view(), name='inbox'),
    
    path('add/listings/', api_views.CarListingCreate.as_view(), name='car-listing-create'),
    path('random/listings/', api_views.RandomListingListView.as_view(), name='random-listing'),
    path('listings/details/<uuid:list_id>/', api_views.ListingDetailView.as_view(), name='listing_details'),
    path('get/active/offer/<int:receiver_id>/', api_views.GetActiveOfferAPIView.as_view(), name='active-offer'),
    path('get/<int:receiver_id>/listing/offer/', api_views.GetListingOfferAPIView.as_view(), name='listing-offer'),

    path('wallet/<int:pk>/add-coins/', api_views.AddCoinsToWalletView.as_view(), name='add-coins'),
    path('wallet/total-coins/', api_views.GetTotalCoinsView.as_view(), name='total-coins'),
    path('wallet/<int:pk>/deduct-coins/', api_views.DeductCoinsView.as_view(), name='deduct-coins'),
    path('listing/<uuid:listing_id>/delete/', api_views.DeleteListingView.as_view(), name='delete-listing'),
    # path('user/listings2/', api_views.FilteredUserListings.as_view(), name='filtered_user_listings'),
    path('listing/<uuid:listing_id>/update-status/', api_views.UpdateListingStatusView.as_view(), name='update-listing-status'),

    path('listings/<str:category>/', api_views.ListingByCategoryView.as_view(), name='listings_by_category'),
    path('listing/searchview/', api_views.ListingSearchView.as_view(), name='ListingSearchView'),

    path('favorites/add/', api_views.AddFavoriteView.as_view(), name='add_favorite'),
    path('favorites/remove/', api_views.RemoveFavoriteView.as_view(), name='remove_favorite'),
    path('favorites/', api_views.FavoritesView.as_view(), name='favorites'),
    path('favorites/mark', api_views.FavoritesMarkView.as_view(), name='favorites_mark'),

    path('user/follow/', api_views.FollowUser.as_view(), name='follow_user'),
    path('user/unfollow/', api_views.UnfollowUser.as_view(), name='unfollow_user'),
    path('follow/mark/', api_views.ListFollowing.as_view(), name='list_followings'),
    path('follower/list/', api_views.ListFollower.as_view(), name='list_follower'),

    path('paypal/onboard/', paypal_views.PaypalOnboard.as_view(), name='paypal_onboard'),
    path('paypal/create/order/', paypal_views.CreatePaypalOrder.as_view(), name='paypal_create_order'),

    # SEAN
    path('create-paypal-order/', api_views.CreatePaypalOrder.as_view(), name='create_paypal_order'),
    path('capture-paypal-order/', api_views.CapturePaypalOrder.as_view(), name='create_paypal_order'),    
    path('paypal-payment-cancelled/', api_views.PaypalPaymentCancelled.as_view(), name='paypal_payment_cancelled'),
    path('refund-first-transaction/', api_views.RefundPayment.as_view(), name='refund-first-transaction'),
    path('transactions/', api_views.TransactionHistoryView.as_view(), name='transaction-history'),
    # path('simple-transfer/', api_views.SendMoneyToUser.as_view(), name='simple-transfer'),
    # path('complete-simple-transfer/', api_views.CheckPayoutStatus.as_view(), name='complete-simple-transfer'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)                    

# {
# "email": "kangpatricia96@gmail.com",
# "password": "tokunoyushi2004"
# }