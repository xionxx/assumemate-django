from django.urls import path, include
from django.conf import settings  
from django.conf.urls.static import static 
from rest_framework.routers import DefaultRouter
from . import api_views
from . import paypal_views
from .api_views import MyTokenObtainPairView, RateUserView, RatingsView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('user-register/', api_views.UserRegister.as_view(), name='user-register'), #register user
    path('login/', api_views.UserLogin.as_view(), name='login'),    #login
    path('token/', MyTokenObtainPairView.as_view(), name='token-obtain-pair'), #generate tokenn
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'), #generate refresh token
    path('logout/', api_views.UserLogout.as_view(), name='logout'),     # logout, way gamit
    path('create-profile/', api_views.UserCreateProfile.as_view(), name='create-profile'),  #create profile
    path('view-profile/', api_views.GetUserProfile.as_view(), name='view-profile'), #get logged in user profile
    path('view/<int:user_id>/profile/', api_views.ViewOtherProfile.as_view(), name='view-other-profile'),   #get other user profile
    path('check/user/email/', api_views.CheckGoogleEmail.as_view(), name='check-email'),    #check email if exist for google register
    path('email-verification/', api_views.UserEmailVerification.as_view(), name='email-verification'),  #sign up email then send verification
    path('check-user-verification/', api_views.CheckUserVerification.as_view(), name='check-user-verification'),    #check if user has email verified
    path('email-verified/page/', api_views.email_verified, name='user-verified-page'),  #render web view for complete email verification
    path('email-verify/<str:verification_code>/', api_views.VerifyEmail.as_view(), name='email-verify'),    #verify email (from sent email)
    path('find-password/', api_views.ResetPasswordLink.as_view(), name='find-password'),    #send reset token to email
    path('change-password/', api_views.ChangePasswordAPIView.as_view(), name='change-password'),    #update password
    path('deactivate/', api_views.DeactivateUserAPIView.as_view(), name='deactivate'),    #update password
    path('update-profile/', api_views.UpdateUserProfile.as_view(), name='update-profile'),  #update profile
    path('update-profile/picture/', api_views.UpdateUserProfilePicture.as_view(), name='update-profile-picture'),   #update profile picture
    path('view-convo/<int:receiver_id>/', api_views.GetMessageAPIView.as_view(), name='view-convo'),    #get entire conversation with the user
    path('make/offer/', api_views.MakeOfferAPIView.as_view(), name='make-offer'),   #make offer
    path('cancel/offer/', api_views.CancelOfferAPIView.as_view(), name='cancel-offer'), #cancel offer for deactivated assumptor
    path('assumptor/list/offers/', api_views.AssumptorListOffers.as_view(), name='assumptor-list-offers'),  #all active offers received by assumptor (own profile)
    path('assumptor/all/<str:list_status>/listings/', api_views.AssumptorListings.as_view(), name='assumptor-lists'), #all listings of assumptor (own profile)
    path('assumptor/<int:user_id>/all/listings/', api_views.AssumptorViewListings.as_view(), name='assumptor-lists'),   #get assumptor's listings (other user viewing)
    path('view/user/inbox/', api_views.UserChatRoomAPIView.as_view(), name='inbox'),    #user's inbox

    path('view/user/application/', api_views.UserEditApplication.as_view(), name='user-application'),    #user's information for edit rejected application
    path('update/user/application/', api_views.UpdateUserApplication.as_view(), name='user-application'),    #user's information for update rejected application
    
    path('add/listings/', api_views.CarListingCreate.as_view(), name='car-listing-create'), #assumptor create listing
    path('random/listings/', api_views.RandomListingListView.as_view(), name='random-listing'), #random listiing in detail screen
    path('listings/details/<uuid:list_id>/', api_views.ListingDetailView.as_view(), name='listing_details'),    #listing details

    #joselito
    path('listings/rejected/<uuid:list_id>/', api_views.ListingRejectedDetailView.as_view(), name='listing_rejected'),    #listing rejected
    path('get/active/offer/<int:receiver_id>/', api_views.GetActiveOfferAPIView.as_view(), name='active-offer'),    #assumee message screen: active offer for that assumptor
    path('get/<int:receiver_id>/listing/offer/', api_views.GetListingOfferAPIView.as_view(), name='listing-offer'), #assumptor message screen: active offer of that assumee

    path('wallet/<int:pk>/add-coins/', api_views.AddCoinsToWalletView.as_view(), name='add-coins'), #add coins assumptor
    path('wallet/total-coins/', api_views.GetTotalCoinsView.as_view(), name='total-coins'), #get total coins
    path('wallet/<int:pk>/deduct-coins/', api_views.DeductCoinsView.as_view(), name='deduct-coins'),    #deduct coins when paying post or promote
    path('listing/<uuid:listing_id>/delete/', api_views.DeleteListingView.as_view(), name='delete-listing'),    #delete/archive listing
    path('assumptor/all/<str:list_status>/app/listings/', api_views.FilteredUserListings.as_view(), name='filtered_user_listings'),   #for pending and to pay listing
    path('listing/<uuid:listing_id>/update-status/', api_views.UpdateListingStatusView.as_view(), name='update-listing-status'),   
    path('listingstats/<uuid:listing_id>/', api_views.ListingStatus.as_view(), name='listing-status'),
    path('promote_listing/', api_views.PromoteListingView.as_view(), name='promote-listing'),
    path('promote/', api_views.PromotedListingsView.as_view(), name='promoted'),
    path('update_listing/<uuid:listing_id>/', api_views.UpdateListingAPIView.as_view(), name='update_listing'),


    path('listings/<str:category>/', api_views.ListingByCategoryView.as_view(), name='listings_by_category'),   #feed screen all active listings
    path('listing/searchview/', api_views.ListingSearchView.as_view(), name='ListingSearchView'),   #search listing

    path('favorites/add/', api_views.AddFavoriteView.as_view(), name='add_favorite'),   #like listing
    path('favorites/remove/', api_views.RemoveFavoriteView.as_view(), name='remove_favorite'),  #unlike listing
    path('favorites/', api_views.FavoritesView.as_view(), name='favorites'),    #

    path('user/follow/', api_views.FollowUser.as_view(), name='follow_user'),   #follow user
    path('user/unfollow/', api_views.UnfollowUser.as_view(), name='unfollow_user'), #unfollow user
    path('follow/mark/', api_views.ListFollowing.as_view(), name='list_followings'),    #followinga list
    path('follower/list/', api_views.ListFollower.as_view(), name='list_follower'), #followers list
    path('send/report/', api_views.ReportView.as_view(), name='send_report'),   #send report
    path('rate/', RateUserView.as_view(), name='rate_user'), #send rate
    path('view/rate', RatingsView.as_view(), name='rate_views'),  #view rate

    path('paypal/onboard/', paypal_views.PaypalOnboard.as_view(), name='paypal_onboard'),   #link paypal
    path('create/order/', api_views.CreateOrder.as_view(), name='create_order'), #create order for offer or buy
    path('cancel/order/<str:order_id>/', api_views.CancelOrder.as_view(), name='cancel_order'),  #cancel order
    path('view/order/<str:order_id>/', api_views.GetOrder.as_view(), name='view_order'),  #view order
    path('create/paypal/order/', paypal_views.CreatePaypalOrder.as_view(), name='view_order'),  #create paypal order
    path('capture/paypal/order/', paypal_views.CapturePaypalOrder.as_view(), name='view_order'),  #pay listing order
    path('cancel/paypal/', paypal_views.PaypalPaymentCancelled.as_view(), name='paypal_payment_cancelled'), #cancel payment

    # SEAN
    path('create-paypal-order/', api_views.CreatePaypalOrder.as_view(), name='create_paypal_order'),    #create order for top-up
    path('capture-paypal-order/', api_views.CapturePaypalOrder.as_view(), name='create_paypal_order'),    #pay top-up
    path('paypal-payment-cancelled/', api_views.PaypalPaymentCancelled.as_view(), name='paypal_payment_cancelled'), #cancel payment
    path('refund-first-transaction/', api_views.RefundPayment.as_view(), name='refund-first-transaction'),  #refund 
    path('transactions/', api_views.TransactionHistoryView.as_view(), name='transaction-history'),  #complete transactions
    # path('simple-transfer/', api_views.SendMoneyToUser.as_view(), name='simple-transfer'),
    # path('complete-simple-transfer/', api_views.CheckPayoutStatus.as_view(), name='complete-simple-transfer'),

    # JERICHO
    path('notifications/', api_views.NotificationListView.as_view(), name='notification-list'), #notificaions
    path('notifications/<int:pk>/read/', api_views.MarkNotificationAsReadView.as_view(), name='mark-notification-read'),    #mark notif as read
    path('save_fcm_token/', api_views.save_fcm_token, name='save_fcm_token'),   #save token
    path('remove_fcm_token/', api_views.remove_fcm_token, name='remove_fcm_token'),   #save token
    path('reports/received/', api_views.ReceivedReportsListView.as_view(), name='reports-received'),
    path('reports/sent/', api_views.SentReportsListView.as_view(), name='reports-sent'),




]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)                    

# {
# "email": "kangpatricia96@gmail.com",
# "password": "tokunoyushi2004"
# }