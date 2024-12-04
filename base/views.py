from io import BytesIO
import json
import os
from PyPDF2 import PdfReader, PdfWriter
from dotenv import load_dotenv
import random, string, cloudinary, base64
from django.views.decorators.csrf import csrf_protect
from reportlab.pdfgen import canvas
from django.db import IntegrityError
from smtplib import SMTPConnectError, SMTPException
import requests as req
from django.contrib.auth.decorators import user_passes_test, login_required
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse
from django.conf import settings
from django.core.mail import EmailMessage
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.db.models import Q, Count, Avg, Count, F, Value, Sum, DecimalField
from .permissions import IsAdminUser
from .models import *
from rest_framework import viewsets, status, permissions
import hashlib
from django.contrib.auth.hashers import check_password
from django.template.loader import render_to_string
from rest_framework.response import Response
from django.db.models.functions import ExtractMonth
from django.core.files.base import ContentFile
from django.db.models import Sum, F, Case, When, FloatField, Count, ExpressionWrapper
from django.contrib.auth import login as login, authenticate, logout, get_user_model, update_session_auth_hash

load_dotenv()
UserModel = get_user_model()

client_id = os.getenv('PAYPAL_CLIENT_ID')
secret_key = os.getenv('PAYPAL_CLIENT_SECRET')
baseURL = os.getenv('PAYPAL_BASE_URL')

def is_admin(user):
    return user.is_staff

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits

    password = ''.join(random.choice(characters) for _ in range(length))

    return password

# Function to generate the PDF content
def create_pdf(user_profile, temp_password):
    buffer = BytesIO()

    # Generate the PDF using ReportLab
    pdf = canvas.Canvas(buffer)
    pdf.drawString(100, 750, "Assumemate Account Details")
    pdf.drawString(100, 730, f"Dear Mr/s. {user_profile.user_prof_lname},")
    pdf.drawString(100, 710, "We are thrilled to welcome you to Assumemate!")
    pdf.drawString(100, 690, "Below are the details for your Assumemate account:")
    pdf.drawString(100, 670, f"Name: {user_profile.user_prof_fname} {user_profile.user_prof_lname}")
    pdf.drawString(100, 650, f"Email Address: {user_profile.user_id.email}")
    pdf.drawString(100, 630, f"Temporary Password: {temp_password}")
    pdf.drawString(100, 610, "Please use this password to log in and change it immediately.")
    
    pdf.save()

    buffer.seek(0)  # Reset buffer to start

    return buffer

def encrypt_pdf(pdf_buffer, user_lastname, user_birthday):
    pdf_reader = PdfReader(pdf_buffer)
    pdf_writer = PdfWriter()

    for page in range(len(pdf_reader.pages)):
        pdf_writer.add_page(pdf_reader.pages[page])

    # Format the password by removing dashes from the birthday
    formatted_birthday = user_birthday.replace('-', '')  # Remove dashes
    encryption_password = f"{user_lastname}{formatted_birthday}"

    # Add password protection
    pdf_writer.encrypt(encryption_password)

    encrypted_pdf_buffer = BytesIO()
    pdf_writer.write(encrypted_pdf_buffer)
    encrypted_pdf_buffer.seek(0)  # Reset buffer to start

    return encrypted_pdf_buffer

def send_welcome_email(user_profile, user_account, temp_password):
    # Create the PDF content
    pdf_buffer = create_pdf(user_profile, temp_password)

    # Encrypt the PDF with the user's last name and formatted birthday
    user_lastname = user_profile.user_prof_lname
    user_birthday = user_profile.user_prof_dob  # Assuming you have birthday in user_profile
    encrypted_pdf_buffer = encrypt_pdf(pdf_buffer, user_lastname, user_birthday)

    # Email content
    message = (
        f'Dear Mr/s. {user_profile.user_prof_lname},\n\n'
        'We are thrilled to welcome you to Assumemate! '
        'Attached is a PDF document with your account details, protected by your last name and birthday.\n'
        'Please use the combination of your last name and birthday to access the document and change your temporary password immediately after logging in.\n\n'
        'Thank you for joining Assumemate!'
    )

    # Save the PDF as a file in memory to attach to the email
    pdf_filename = f"Assumemate_Account_Details_{user_profile.user_prof_lname}.pdf"
    pdf_file = encrypted_pdf_buffer

    try:
        # Send the email with the encrypted PDF attached
        email = EmailMessage(
            'Welcome to Assumemate - Your Account Details',
            message,
            settings.EMAIL_HOST_USER,
            [user_account.email]
        )
        email.attach(pdf_filename, pdf_file.getvalue(), 'application/pdf')
        email.send(fail_silently=False)

        print(f"Email sent to {user_account.email}")
        
    except Exception as e:
        print('Error sending welcome email with PDF:', e)
        return JsonResponse({'error': f'Error sending welcome email with PDF: {e}'})

# @login_required
# @user_passes_test(is_admin)
@csrf_protect
def upperuser_register(request, user_type):
    if request.method == 'POST':
        try:
            fname = request.POST.get('fname').title()
            lname = request.POST.get('lname').title()
            gender = request.POST.get('gender').title()
            address = request.POST.get('address').title()
            dob = request.POST.get('bday')
            mobile = request.POST.get('phone')
            email = request.POST.get('email').lower()
            # image = request.FILES.get('imagefile')
            user_image = request.POST.get('user_image')
            password = generate_random_password()
            
            user = UserModel.objects.create(email=email, first_name=fname,
                                last_name=lname, is_superuser=True, is_active=True)
            
            if user_type == 'Admin':
                user.is_staff=True
            elif user_type == 'Reviewer':
                user.is_reviewer=True
            
            user.set_password(password)
            user.save()

            folder_name = f"{fname} {lname} ({user.id})"

            if user_image:
                try:
                    format, imgstr = user_image.split(';base64,') 
                    ext = format.split('/')[-1]  # Extract the image extension (jpeg, png, etc.)
                    # Decode the image
                    image_data = ContentFile(base64.b64decode(imgstr), name=f"user{user.id}_{fname}_{lname}.{ext}")

                    upload_result = cloudinary.uploader.upload(image_data, folder=f"user_images/{folder_name}")
                except Exception as e:
                    return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            image_json =  upload_result['secure_url'] if image_data else None

            profile = UserProfile.objects.create(user_prof_fname=fname, user_prof_lname=lname, user_prof_gender=gender, 
                                                 user_prof_dob=dob, user_prof_mobile=mobile, user_prof_address=address, 
                                                 user_prof_pic=image_json, user_prof_valid_pic=image_json, user_id=user)
            
            profile.save()
            try:
                send_welcome_email(profile, user, password)
            except Exception as e:
                print(e)
                return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return JsonResponse({'message': 'User added successfully'}, status=status.HTTP_201_CREATED)

        except IntegrityError:
            return JsonResponse({'error': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@csrf_protect
def user_login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        print(email)
        print(password)

        user = authenticate(request, email=email, password=password)
        print(user)
        if user is not None:
            login(request, user)
            return JsonResponse({'redirect': '/dashboard/'})
        else:
            print("Authentication failed")
            return JsonResponse({'auth_failed': 'Incorrect email or password'})
        
    return render(request, 'base/login.html')

@login_required
def edit_profile(request):
    profile = request.user.profile
    context = {'user': request.user, 'profile': profile}
    return render(request, 'base/edit_profile.html', context)

@login_required
def update_profile(request):
    if request.method == 'POST':
        address = request.POST.get('address')
        mobile = request.POST.get('mobile')

        user = request.user

        user.profile.user_prof_address = address
        user.profile.user_prof_mobile = mobile
        user.profile.save()

        # messages.success(request, "Account has been updated successfully")

        return JsonResponse({'message': 'Account has been updated successfully'}, status=status.HTTP_200_OK)

    return HttpResponse('Bad request', status=400)

@login_required
def change_password(request):
    if request.method == 'POST':
        user = request.user
        new_password = request.POST.get('newpass')
        curpass = request.POST.get('curpass')
        confirm_password = request.POST.get('confirmpass')

        print(new_password)

        if not check_password(curpass, user.password):
            return JsonResponse({'error': 'Current password does not match.'})
        else:
            if new_password and confirm_password and new_password == confirm_password:
                if curpass == new_password:
                    return JsonResponse({'error':  'New password should not match current password.'})
                else:
                # Update user password
                    user.password = new_password
                    user.save()
                    request.user.set_password(new_password)
                    request.user.save()
                    # Update the session to prevent the user from being logged out
                    update_session_auth_hash(request, request.user)

                    return JsonResponse({'message':  'Password updated successfully.'})

    # return redirect('edit_profile')
    return JsonResponse({'error':  'bad request'})

def reset_password_page(request):
    try:
        user = request.GET.get('key')
        token = request.GET.get('token')
        is_expired = False

        if not user or not token:
            return redirect('forgot_password')

        try:
            user_id = int(urlsafe_base64_decode(user).decode('utf-8'))
        except (TypeError, ValueError, OverflowError):
            return redirect('forgot_password')
        
        try:
            verification = PasswordResetToken.objects.get(user_id=user_id)

            if not verification.reset_token or verification.reset_token != token or verification.reset_token_expires_at < timezone.now():
                is_expired = True
        except PasswordResetToken.DoesNotExist:
            is_expired = True

        return render(request, 'base/create_new_password.html', context={'is_expired': is_expired, 'key': user, 'token': token})
    
    except Exception as e:
        return redirect('forgot_password')

@login_required
def pending_accounts_view(request):
    pending_applications = UserApplication.objects.filter(user_app_status='PENDING')
    pending_assumptors = pending_applications.filter(user_id__is_assumptor=True)
    pending_assumees = pending_applications.filter(user_id__is_assumee=True)
    context = {
        'pending_assumptors': pending_assumptors,
        'pending_assumees': pending_assumees,
        'nav': 'pending_user'
    }
    
    return render(request, 'base/rev_pending_users.html', context)

@login_required
def assumemate_rev_report_users(request):
    reports = Report.objects.filter(report_status='PENDING')
    context = {
        'reports': reports,
        'nav': 'reports',
    }
    return render(request, 'base/rev_reported_users.html', context)

@login_required
def user_detail_view(request, user_id):
    user = get_object_or_404(UserAccount, pk=user_id)
    print(user.profile.user_prof_valid_pic)
    return render(request, 'base/user_detail.html', {'user': user})

@login_required
def assumemate_users(request):
    status = request.GET.get('status', 'all')  # Get the selected category
    application = UserApplication.objects.select_related('user_id', 'user_app_reviewer_id')

    # Filter based on status
    if status == 'Assumptors':
        application = application.filter(user_id__is_assumptor=True)
    elif status == 'Assumees':
        application = application.filter(user_id__is_assumee=True)
    elif status == 'Suspend':
        application = application.filter(user_app_status='SUSPENDED')  # Modify if suspend logic is different
    else:
        application = application.filter(
            Q(user_id__is_assumptor=True) | Q(user_id__is_assumee=True)
        )

    # User count stats
    assumptor_count = UserModel.objects.filter(is_assumptor=True).count()
    assumee_count = UserModel.objects.filter(is_assumee=True).count()
    isadmin_count = UserModel.objects.filter(is_staff=True).count()
    isreviewer_count = UserModel.objects.filter(is_reviewer=True).count()
    total_user = assumptor_count + assumee_count

    # Prepare context data
    context = {
        'assumptor_count': assumptor_count,
        'assumee_count': assumee_count,
        'isadmin_count': isadmin_count,
        'isreviewer_count': isreviewer_count,
        'total_user': total_user,
        'application': application,
        'nav': 'user'
    }

    return render(request, 'base/users.html', context)

@login_required
def assumemate_listing(request):

    current_date = timezone.now()
    # Handle search functionality and category filtering
    search_query = request.GET.get('search', '')
    selected_category = request.GET.get('category', 'all')

    # Base queryset for listings
    listings = Listing.objects.all().order_by('list_id')

    if search_query:
        listings = listings.filter(list_content__title__icontains=search_query)

    if selected_category != 'all':
        listings = listings.filter(list_content__category=selected_category)

    # Retrieve counts for all categories irrespective of filtering
    category_counts = Listing.objects.values('list_content__category').annotate(count=Count('list_id'))
    category_count_dict = {cat['list_content__category']: cat['count'] for cat in category_counts}

    # Get counts for each specific category with a default of zero
    house_and_lot_count = category_count_dict.get('Real Estate', 0)
    cars_count = category_count_dict.get('Car', 0)
    motorcycles_count = category_count_dict.get('Motorcycle', 0)

    # Retrieve all distinct categories for the dropdown
    categories = Listing.objects.values('list_content__category').distinct()


    for listing in listings:
        # Check if the listing has a promotion
        promotion = PromoteListing.objects.filter(list_id=listing).first()
        if promotion:
            # If the promotion end date is in the past, set is_promoted to False
            if promotion.prom_end < current_date:
                listing.is_promoted = False
                listing.days_remaining = 0  # No days remaining if promotion has ended
            else:
                listing.is_promoted = True
                # Calculate the remaining days
                days_remaining = (promotion.prom_end - current_date).days
                listing.days_remaining = max(days_remaining, 0)  # Ensure it's not negative
        else:
            listing.is_promoted = False
            listing.days_remaining = 0  # No promotion found

    context = {
        'listings': listings,
        'categories': categories,
        'selected_category': selected_category,
        'house_and_lot_count': house_and_lot_count,
        'motorcycles_count': motorcycles_count,
        'cars_count': cars_count,
        'nav': 'listing'
    }

    return render(request, 'base/listing.html', context)

@login_required
def users_view_details(request, user_id):
    current_date = timezone.now()
    user_id = UserModel.objects.get(id=user_id)
    print(f"Requested user_id: {user_id}")  # Debugging line
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    user_details = UserApplication.objects.select_related('user_id', 'user_app_reviewer_id').filter(user_id=user_id).first()
    
    # Fetch listings posted by this user (Assumptor)
    user_listings = Listing.objects.filter(user_id=user_profile.user_id)

    for listing in user_listings:
        # Check if the listing has a promotion
        promotion = PromoteListing.objects.filter(list_id=listing).first()
        if promotion:
            # If the promotion end date is in the past, set is_promoted to False
            if promotion.prom_end < current_date:
                listing.is_promoted = False
                listing.days_remaining = 0  # No days remaining if promotion has ended
            else:
                listing.is_promoted = True
                # Calculate the remaining days
                days_remaining = (promotion.prom_end - current_date).days
                listing.days_remaining = max(days_remaining, 0)  # Ensure it's not negative
        else:
            listing.is_promoted = False
            listing.days_remaining = 0  # No promotion found

    context = {
        'user_profile': user_profile,
        'user_details': user_details,
        'user_listings': user_listings,  # Pass listings to template
    }
    
    return render(request, 'base/users_view_details.html', context)

def reject_report(request, report_id):
    if request.method == 'POST':
        report = get_object_or_404(Report, report_id=report_id)
        report.report_status = 'REJECTED'
        report.updated_at = timezone.now() 
        report.report_reason = request.POST.get('report_reason', '')  
        report.save()
        
        messages.success(request, 'Report has been rejected.')
        return redirect('assumemate_rev_report_users')  

    messages.error(request, 'Invalid request method.')
    return redirect('some_error_view') 

@login_required
def report_detail_view(request, report_id):
    # Fetch the report object
    userreport = get_object_or_404(Report, pk=report_id)
    
    # Extract reporter_id and reported_user_id from the JSON field in report_details
    reporter_id = userreport.report_details.get('reporter_id', None)
    reported_user_id = userreport.report_details.get('reported_user_id', None)
    
    # Fetch the UserAccount and Profile for the reporter
    user = None
    user_profile = None
    if reporter_id:
        try:
            user = UserAccount.objects.get(id=reporter_id)
            user_profile = user.profile  # Access the related profile
        except UserAccount.DoesNotExist:
            user = None
            user_profile = None

    # Fetch the UserAccount and Profile for the reported user
    reported_user = None
    reported_user_profile = None
    if reported_user_id:
        try:
            reported_user = UserAccount.objects.get(id=reported_user_id)
            reported_user_profile = reported_user.profile  # Access the related profile
        except UserAccount.DoesNotExist:
            reported_user = None
            reported_user_profile = None

    # Pass both the reporter and reported user profiles to the template context
    return render(request, 'base/report_detail.html', {
        'userreport': userreport,
        'user': user,
        'user_profile': user_profile,
        'reported_user': reported_user,
        'reported_user_profile': reported_user_profile
    })


@login_required
def platform_report(request):

    assumptors_count = UserAccount.objects.filter(is_assumptor=True).count()
    assumees_count = UserAccount.objects.filter(is_assumee=True).count()
    total_users_count = UserAccount.objects.filter(Q(is_assumptor=True) | Q(is_assumee=True)).count()
    admins_count = UserAccount.objects.filter(is_superuser=True).count()
    reviewers_count = UserAccount.objects.filter(is_reviewer=True).count()
    active_accounts_count = UserAccount.objects.filter(Q(is_active=True) & (Q(is_assumptor=True) | Q(is_assumee=True))).count()
    inactive_accounts_count = UserAccount.objects.filter(Q(is_active=False) & (Q(is_assumptor=True) | Q(is_assumee=True))).count()
    promoted_listings_count = PromoteListing.objects.count()

    user_growth_data = UserAccount.objects.annotate(month=ExtractMonth('date_joined')) \
        .values('month') \
        .annotate(count=Count('id')) \
        .order_by('month')

    user_type_data = UserAccount.objects.annotate(month=ExtractMonth('date_joined')) \
        .values('month') \
        .annotate(
            assumptors_count=Count('id', filter=Q(is_assumptor=True)),
            assumees_count=Count('id', filter=Q(is_assumee=True))
        ).order_by('month')

    months = []
    assumptors_counts = []
    assumees_counts = []

    for entry in user_type_data:
        months.append(entry['month'])
        assumptors_counts.append(entry['assumptors_count'])
        assumees_counts.append(entry['assumees_count'])


    months_growth = []
    user_counts = []
    for entry in user_growth_data:
        months_growth.append(entry['month'])
        user_counts.append(entry['count'])

    context = {
        'assumptors_count': assumptors_count,
        'assumees_count': assumees_count,
        'total_users_count': total_users_count,
        'admins_count': admins_count,
        'reviewers_count': reviewers_count,
        'active_accounts_count': active_accounts_count,
        'inactive_accounts_count': inactive_accounts_count,
        'promoted_listings_count': promoted_listings_count,
        'months': months_growth,
        'user_counts': user_counts,
        'assumptors_counts': assumptors_counts,
        'assumees_counts': assumees_counts,
        'nav': 'report'
    }
    return render(request, 'base/reports.html', context)

@login_required
def listing_view_details(request, user_id, list_id):
    current_date = timezone.now()


    print(f"Requested listing user_id: {user_id}")
    print(f"Requested listing list_id: {list_id}")


    listing = get_object_or_404(Listing, user_id=user_id, list_id=list_id)

    # Debug: Print the listing to verify it's being fetched correctly
    print(f"Listing fetched: {listing.list_content}")

    # Fetch the first related reviewer application for this listing
    reviewer = ListingApplication.objects.filter(list_id=listing).first()

    # Fetch the user profile for the assumptor
    user_profile = get_object_or_404(UserProfile, user_id=user_id)

    # Fetch all listings by the same assumptor
    user_listings = Listing.objects.filter(user_id=user_id, list_id = list_id)
    assumptor_listing = Listing.objects.filter(user_id = user_id)

    # Promotion logic
    for listing in user_listings:
        promotion = PromoteListing.objects.filter(list_id=listing).first()
        if promotion:
            if promotion.prom_end < current_date:
                listing.is_promoted = False
                listing.days_remaining = 0
            else:
                listing.is_promoted = True
                days_remaining = (promotion.prom_end - current_date).days
                listing.days_remaining = max(days_remaining, 0)
        else:
            listing.is_promoted = False
            listing.days_remaining = 0

    context = {
        'user_profile': user_profile,
        'listing': listing,
        'reviewer': reviewer,
        'user_listings': user_listings,
        'assumptor_listing': assumptor_listing,
    }
    return render(request, 'base/listing_view_details.html', context)

@login_required
def assumemate_rev_pending_list(request):
    pending_listings = ListingApplication.objects.filter(list_app_status='PENDING').select_related('list_id')
    
    context = {
        'pending_listings': pending_listings,
        'nav': 'pending_list'
    }
    
    return render(request, 'base/rev_pending_listing.html', context)

@login_required
def logout_user(request):
    if request.user.is_authenticated:
        logout(request)
        return redirect(user_login)

@login_required
def usertype_is_active(request, admin_id, status):

    user = UserModel.objects.get(id=admin_id)

    user.is_active = status
    user.save()
    
    # Redirect based on user type
    if user.is_staff:  # If the user is an Admin
        return redirect('admin_acc_list')  # Redirect to admin account list
    elif user.is_reviewer:  # If the user is a Reviewer
        return redirect('reviewer_acc_list') 


@login_required
def base(request):
    context = {'nav': 'home'}
    return render(request, "base/home.html", context)

# @user_passes_test(is_admin)
# @login_required
def admin_acc_create(request):
    context = {'nav': 'admin', 'user_type': 'Admin'}
    return render(request, 'base/add_upperuser.html', context)

@login_required
@user_passes_test(is_admin)
def admin_acc_list(request):
    status = request.GET.get('status', 'all')
    current_user = request.user  

    if status == 'Active':
        admin = UserModel.objects.filter(is_staff=True, is_active=True).exclude(id=current_user.id)
    elif status == 'Inactive':
        admin = UserModel.objects.filter(is_staff=True, is_active=False).exclude(id=current_user.id)
    else:
        admin = UserModel.objects.filter(is_staff=True).exclude(id=current_user.id)
    
    context = {'admin': admin, 'nav': 'admin'}
    return render(request, 'base/admin_list.html', context)

@login_required
# @user_passes_test(is_admin)
def user_application_list(request):
    user_application = UserModel.objects.filter(is_staff=True)
    context = {'users': user_application, 'nav': 'user'}
    # context = {'nav': 'admin'}
    return render(request, 'base/users_list.html', context)

@login_required
@user_passes_test(is_admin)
def reviewer_acc_list(request):
    status = request.GET.get('status', 'all')  # Get the filter status from the request
    if status == 'Active':
        reviewer = UserModel.objects.filter(is_reviewer=True, is_active=True).order_by('-date_joined')
    elif status == 'Inactive':
        reviewer = UserModel.objects.filter(is_reviewer=True, is_active=False).order_by('-date_joined')
    else:
        reviewer = UserModel.objects.filter(is_reviewer=True).order_by('-date_joined')
    
    context = {'reviewer': reviewer, 'nav': 'reviewer'}  # Ensure this matches your template
    return render(request, 'base/reviewer_list.html', context)

@login_required
@user_passes_test(is_admin)
def reviewer_acc_create(request):
    context = {'nav': 'reviewer', 'user_type': 'Reviewer'}
    return render(request, 'base/add_upperuser.html', context)

def forgot_password(request):
    # return render(request, 'base/reset_link_template.html')
    return render(request, 'base/find_password.html')

def send_reset_link(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return JsonResponse({'error': 'User not found.', 'status': 404})
        
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        PasswordResetToken.objects.update_or_create(
        user=user,
        defaults={
            'reset_token': token,
            'reset_token_expires_at': timezone.now() + timedelta(hours=1),
            'reset_token_created_at': timezone.now()
            }
        )
        
        base_url = os.getenv('API_URL')
        template_name  = 'base/reset_link_template.html'
        reset_link = f'{base_url}/reset-password?key={uidb64}&token={token}'
        context = {'name': user.profile.user_prof_fname, 'link': reset_link}
        email_content =  render_to_string(
            template_name=template_name,
            context=context
            )
        
        print(base_url)
        print(reset_link)
        
        email_message = EmailMessage(
        subject='[ASSUMATE Account] Password reset request',
        body=email_content,
        from_email=settings.EMAIL_HOST_USER,
        to=[email],
            )
        
        email_message.content_subtype = 'html'

        email_message.send(fail_silently=False)

        return JsonResponse({'message': 'Password reset request sent!', 'status': 200})
    else:
        return JsonResponse({'error': 'Invalid request method.', 'status': 400})
    
def reset_password(request):
    if request.method == 'POST':
        user_uid64 = request.GET.get('key')

        token = request.GET.get('token')
        newpass = request.POST.get('newpass')

        try:
            user_id = int(urlsafe_base64_decode(user_uid64).decode('utf-8'))
        except (TypeError, ValueError, OverflowError):
            return JsonResponse({'error': 'Invalid user ID.', 'status': 400})

        try:
            user = UserModel.objects.get(id=user_id)
        except UserModel.DoesNotExist:
            return JsonResponse({'error': 'User not found.', 'status': 404})
        
        try:
            pass_reset = PasswordResetToken.objects.get(Q(user=user.id) & Q(reset_token=token))
            if pass_reset.reset_token_expires_at < timezone.now():
                return JsonResponse({'error': 'Link has expired', 'status': 400})
        except PasswordResetToken.DoesNotExist:
            return JsonResponse({'error': 'Invalid or expired token.', 'status': 400})

        user.set_password(newpass)
        user.save()
        
        pass_reset.reset_token = ''
        pass_reset.reset_token_expires_at = None
        pass_reset.reset_token_created_at = None
        pass_reset.save()
        
        template_name  = 'base/pass_reset_done_template.html'
        context = {'name': user.profile.user_prof_fname}
        email_content =  render_to_string(
            template_name=template_name,
            context=context
            )
        
        email_message = EmailMessage(
        subject='[ASSUMATE Account] Password reset successful',
        body=email_content,
        from_email=settings.EMAIL_HOST_USER,
        to=[user.email],
            )
        
        email_message.content_subtype = 'html'

        email_message.send(fail_silently=False)

        return JsonResponse({'message': 'Password reset successful.', 'status': 200})
    else:
        return render(request, 'base/create_new_password.html', context={'is_expired': False})

def reset_pass_done(request):
    return render(request, 'base/pass_reset_done.html')

def paypal_return_link(request):
    user_id = request.GET.get('merchantId')
    user = UserModel.objects.get(id=user_id)
    merchant_id = request.GET.get('merchantIdInPayPal')

    hashed_merchant_id = hashlib.sha256(merchant_id.encode()).hexdigest()

    Paypal.objects.create(user_id=user, paypal_merchant_id=hashed_merchant_id)

    return render(request, 'base/onboarding_success.html')

#JERICHO
def assumemate_rev_pending_users(request):
    context={}
    return render(request, 'base/rev_pending_users.html', context)

@login_required
def listing_detail_view(request, list_app_id):
    print(list_app_id)
    listing_application = get_object_or_404(ListingApplication, list_app_id=list_app_id)
    listing = get_object_or_404(Listing, list_id=listing_application.list_id_id)

    pending_listings = ListingApplication.objects.filter(list_app_status='PENDING')

    context = {
        'listing': listing,
        'listing_application': listing_application,
        'pending_listings': pending_listings,
    }
    return render(request, 'base/listing_detail.html', context)

@login_required
def accept_listing(request, list_app_id):
    if request.method == 'POST':
        listing_application = get_object_or_404(ListingApplication, list_app_id=list_app_id)
        listing_application.list_app_status = 'APPROVED'
        listing_application.list_reason = request.POST.get('list_reason', '')  
        listing_application.list_app_reviewer_id = request.user

        listing = listing_application.list_id
        assumptor_user = listing.user_id
        current_date = timezone.now()
        current_year = current_date.year
        current_month = current_date.month

        existing_listings = ListingApplication.objects.filter(
            list_id__user_id=assumptor_user,
            list_app_date__year=current_year,
            list_app_date__month=current_month,
            list_app_status='APPROVED'
        ).exclude(list_app_id=list_app_id)

        if not existing_listings.exists():
            listing.list_status = 'ACTIVE' 
            listing.list_duration = timezone.now() + timedelta(days=30)
        else:
            listing.list_status = 'PENDING'  

        listing_application.save()
        listing.save()

        user_account = listing.user_id
        fcm_token = user_account.fcm_token  

        if fcm_token:
            title = 'Listing Application approved'
            message = 'Your Listing Application has been approved.'
            
            listing_images = listing.list_content.get('images', [])
            first_image_url = listing_images[0] if listing_images else None

            data_payload = {
                "route": "/listings/details/",
                "listingId": str(listing.list_id),  
                "userId": str(assumptor_user.id)      
            }
            send_push_notification(fcm_token, title, message, image_url=first_image_url, data_payload=data_payload)

        # Display success message and redirect
        messages.success(request, 'Listing application has been approved.')
        return redirect('assumemate_rev_pending_list')

    messages.error(request, 'Invalid request method.')
    return redirect('some_error_view')


@login_required
def reject_listing(request, list_app_id):
    if request.method == 'POST':
        listing_application = get_object_or_404(ListingApplication, list_app_id=list_app_id)

        listing_application.list_app_status = 'REJECTED'
        listing_application.list_reason = request.POST.get('list_reason', '')  
        listing_application.save()

        listing = listing_application.list_id
        user_account = listing.user_id
        fcm_token = user_account.fcm_token  

        if fcm_token:
            title = 'Listing Application rejected'
            message = f'Your Listing Application has been rejected.'
            
            listing_images = listing.list_content.get('images', [])
            first_image_url = listing_images[0] if listing_images else None

            data_payload = {
                "route": "/listings/details/",
                "listingId": str(listing.list_id),  
                "userId": str(user_account.id)      
            }

            send_push_notification(fcm_token, title, message, image_url=first_image_url, data_payload=data_payload)
        
    messages.success(request, 'Listing application has been rejected.')
    return redirect('assumemate_rev_pending_list')

@login_required
def accept_user(request, user_id):
    user_application = get_object_or_404(UserApplication, user_id=user_id)
    user_application.user_app_status = 'APPROVED'
    user_application.user_app_approved_at = timezone.now()
    user_application.user_app_reviewer_id = request.user  

    user_application.save()
    user_account = user_application.user_id
    user_account.is_active = True
    user_account.save()

   
    fcm_token = user_account.fcm_token 

    if fcm_token:

        title = 'Application Approved'
        message = 'Your user application has been approved.'
        data_payload = {  
                'application_status': 'APPROVED',  
            }
        send_push_notification(fcm_token, title, message, data_payload=data_payload)
    

    messages.success(request, 'User application has been approved.')
    return redirect('pending_accounts_view')

@login_required
def reject_user(request, user_id):
    if request.method == 'POST':
        user_application = get_object_or_404(UserApplication, user_id=user_id)
        user_application.user_app_status = 'REJECTED'
        user_application.user_app_declined_at = timezone.now()
        user_application.user_reason = request.POST.get('user_reason', '')  
        user_application.user_app_reviewer_id = request.user
        user_application.save()

        user_account = user_application.user_id
        fcm_token = user_account.fcm_token 

        if fcm_token:

            title = 'Application Rejected'
            message = 'Your user application has been rejected.'
            data_payload = {  
                    'application_status': 'REJECTED',  
                }
            send_push_notification(fcm_token, title, message, data_payload=data_payload)

        messages.success(request, 'User application has been rejected.')
        return redirect('pending_accounts_view')

    messages.error(request, 'Invalid request method.')
    return redirect('pending_accounts_view')

@login_required
def revenue_details(request):
    # Filter the relevant transactions for 'RESERVATION' or 'PAYOUT' types
    transactions = Transaction.objects.filter(transaction_type__in=['RESERVATION', 'PAYOUT'])

    # Perform the annotations and calculations with explicit output_field for each operation
    revenue_data = transactions.annotate(
        paypal_fee=ExpressionWrapper(
            F('transaction_amount') * 0.0349, 
            output_field=DecimalField(max_digits=10, decimal_places=2)
        ),
        fixed_fee=Case(
            When(transaction_type="RESERVATION", then=Value(25)),
            default=Value(12.5),
            output_field=DecimalField(max_digits=10, decimal_places=2)
        ),
        platform_share=ExpressionWrapper(
            F('transaction_amount') * 0.05,
            output_field=DecimalField(max_digits=10, decimal_places=2)
        )
    ).annotate(
        # Define the output_field for the revenue calculation
        revenue=ExpressionWrapper(
            F('platform_share') - F('paypal_fee') - F('fixed_fee'),
            output_field=DecimalField(max_digits=10, decimal_places=2)
        )
    )

    # Sum up the total revenue
    total_revenue = revenue_data.aggregate(total_revenue=Sum('revenue'))['total_revenue'] or 0

    context = {
        'revenue_data': revenue_data,
        'total_revenue': total_revenue,
    }

    return render(request, 'base/revenue_details.html', context)

@login_required
def accept_report(request, report_id):
    report = get_object_or_404(Report, report_id=report_id)
    report.report_status = 'APPROVED'
    report.updated_at = timezone.now()
    report.reviewer = request.user # toy mao rani ibutang para sa katung reviewer i edit lang iif unsay fieldname nimo sa reviewer
    report.save()
    messages.success(request, 'Report has been approved.')
    return redirect('assumemate_rev_report_users')  

@login_required
def reject_report(request, report_id):
    if request.method == 'POST':
        report = get_object_or_404(Report, report_id=report_id)

        # Parse predefined reasons from JSON
        predefined_reasons = request.POST.get('report_reason', '[]')
        try:
            reasons = json.loads(predefined_reasons)
        except json.JSONDecodeError:
            reasons = []

        # Get the "Other" reason
        other_reason = request.POST.get('other_reason', '').strip()

        # Combine into a structured JSON
        report_reasons = {
            "predefined": reasons,
            "other": other_reason if other_reason else None
        }

        # Update the report object
        report.report_status = 'REJECTED'
        report.updated_at = timezone.now()
        report.reviewer = request.user
        report.report_reason = report_reasons  # Save reasons as JSON
        report.save()

        messages.success(request, 'Report has been rejected.')
        return redirect('assumemate_rev_report_users')

    messages.error(request, 'Invalid request method.')
    return redirect('some_error_view')



 #JOSELITO

@login_required
def dashboard(request):
    profiles = UserProfile.objects.filter(
        user_id__ratings_received__rating_value__gte=4.5  # Filter users with rating >= 4.5
    ).annotate(
        average_rating=Avg('user_id__ratings_received__rating_value')  # Calculate the average rating
    ).filter(average_rating__gte=4.5, average_rating__lte=5.0)  # Filter out users with ratings below 4.5 or above 5.0

    # Manually calculate and round the average rating for each profile
    for profile in profiles:
        ratings = [rating.rating_value for rating in profile.user_id.ratings_received.all()]
        profile.calculated_avg = round(sum(ratings) / len(ratings) if ratings else 0, 1)

    # Count of pending Assumptor applications
    pending_assumee_count = UserApplication.objects.filter(user_app_status="PENDING",user_id__is_assumee=True).count()

    # Count of pending Assumptor applications
    pending_assumptor_count = UserApplication.objects.filter(user_app_status="PENDING",user_id__is_assumptor=True).count()

    #Count of pedning Listing applications
    pending_listings_count = ListingApplication.objects.filter(list_app_status="PENDING").count()

    #total pending application
    total_pending = pending_assumee_count + pending_assumptor_count + pending_listings_count

    #most promoted listing
     # Filter promoted listings that have been approved
    approved_promoted_listings = PromoteListing.objects.filter(
        list_id__list_status="ACTIVE"
    ).select_related('list_id')

    # Count listings in each category to find the most promoted
    most_promoted_category = approved_promoted_listings.values(
        category=F('list_id__list_content__category')
    ).annotate(category_count=Count('list_id')).order_by('-category_count').first()

    # Calculate percentage of approved promoted listings
    total_promoted_count = PromoteListing.objects.count()
    approved_percentage = round((approved_promoted_listings.count() / total_promoted_count) * 100) if total_promoted_count > 0 else 0

    gender_count_M = UserProfile.objects.filter(user_prof_gender = "Male").count()
    gender_count_F = UserProfile.objects.filter(user_prof_gender = "Female").count()

    #doughnut category
    real_estate_count = Listing.objects.filter(list_content__category="Real Estate", list_status="active").count()
    motorcycle_count = Listing.objects.filter(list_content__category="Motorcycle", list_status="active").count()
    car_count = Listing.objects.filter(list_content__category="Car", list_status="active").count()
    total_category = real_estate_count + motorcycle_count + car_count

    # Get suspended user count
    suspended_user_count = SuspendedUser.objects.count()

    # Get the total number of reported users
    total_reported_users = Report.objects.count()

    # Get the number of reported users with 'APPROVED' status
    approved_reports = Report.objects.filter(report_status='APPROVED').count()

    # Get the number of reported users with 'PENDING' status
    pending_reports = Report.objects.filter(report_status='PENDING').count()

    # Calculate percentages (you can adjust these as needed)
    if total_reported_users > 0:
        report_user_percentage = (approved_reports / total_reported_users) * 100
    else:
        report_user_percentage = 0

    if suspended_user_count > 0:
        suspended_user_percentage = (suspended_user_count / total_reported_users) * 100
    else:
        suspended_user_percentage = 0

    transactions = Transaction.objects.filter(
        transaction_type__in=["RESERVATION", "PAYOUT"]
    ).annotate(
        paypal_fee=ExpressionWrapper(
            F('transaction_amount') * 0.0349, 
            output_field=DecimalField(max_digits=10, decimal_places=2)
        ),
        fixed_fee=Case(
            When(transaction_type="RESERVATION", then=Value(25)),
            default=Value(12.5),
            output_field=DecimalField(max_digits=10, decimal_places=2)
        ),
        platform_share=ExpressionWrapper(
            F('transaction_amount') * 0.05, 
            output_field=DecimalField(max_digits=10, decimal_places=2)
        )
    ).annotate(
        revenue=ExpressionWrapper(
            F('platform_share') - F('paypal_fee') - F('fixed_fee'),
            output_field=DecimalField(max_digits=10, decimal_places=2)
        )
    )

    # Calculate total revenue
    total_revenue = transactions.aggregate(total_revenue=Sum('revenue'))['total_revenue'] or 0
    print('Total Revenue: ' + str(total_revenue))




    # Pass the counts to the template context
    context = {
        'real_estate_count': real_estate_count,
        'motorcycle_count': motorcycle_count,
        'car_count': car_count,
        'total_category': total_category, 
        'gender_count_M': gender_count_M,
        'gender_count_F' : gender_count_F,
        'pending_assumee_count' : pending_assumee_count,
        'pending_assumptor_count' : pending_assumptor_count,
        'pending_listings_count' : pending_listings_count,
        'total_pending' : total_pending,
        'approved_percentage': approved_percentage,
        'most_promoted_category': most_promoted_category['category'] if most_promoted_category else None,
        'category_count': most_promoted_category['category_count'] if most_promoted_category else 0,
        'profiles' : profiles, #most user's rate

        'report_user_percentage': report_user_percentage,
        'suspended_user_percentage': suspended_user_percentage,
        'suspended_user_count': suspended_user_count,
        'approved_reports': approved_reports,
        'pending_reports': pending_reports,
        'total_revenue': round(total_revenue, 2),  # Add revenue here
        'nav': 'home'
    }
    return render(request, 'base/dashboard.html', context)

@login_required
def admin_details(request, admin_id):
    try:
        admin = UserAccount.objects.get(id=admin_id)
    except UserAccount.DoesNotExist:
        return HttpResponse("Admin not found")
    context ={'admin': admin, 'nav': 'admin'}
    return render(request, 'base/admin_deets.html', context)

@login_required
def reviewer_details(request, reviewer_id):
    try:
        reviewer = UserModel.objects.get(id=reviewer_id)
    except UserModel.DoesNotExist:
        return HttpResponse("Reviewer not found")
    context ={'reviewer': reviewer, 'nav': 'reviewer'}
    return render(request, 'base/reviewer_deets.html', context)

@login_required
def toggle_user_status(request, user_id, user_type, status):
    user_model = UserModel  # Replace this with your actual model if different
    user = user_model.objects.get(id=user_id)
    user.is_active = status
    user.save()

    # Redirect based on user_type
    if user_type == 'admin?':
        return redirect('admin_acc_list')
    elif user_type == 'reviewer':
        return redirect('reviewer_acc_list')
    
@login_required
@user_passes_test(is_admin)
def payout_requests_lists(request):
    payout_requests = PayoutRequest.objects.all()  # Fetch all payout requests
    return render(request, 'base/payout_requests.html', {'payout_requests': payout_requests, 'nav': 'payout'})

@login_required
@user_passes_test(is_admin)
def payout_requests_details(request, payout_id):
    try:
        payout_details = PayoutRequest.objects.get(payout_id=payout_id)  # Fetch all payout requests
        payout_details.payout_fee = float(payout_details.order_id.order_price) * 0.05
        payout_details.payout_amount_after_fee = float(payout_details.order_id.order_price) * 0.95
        return render(request, 'base/payout_request_details.html', {'payout_details': payout_details, 'nav': 'payout'})
    except PayoutRequest.DoesNotExist:
        return
    
def get_paypal_access_token():
    url =  f"{baseURL}/v1/oauth2/token"
    headers = {"Accept": "application/json", "Accept-Language": "en_US"}
    auth = (client_id, secret_key)
    data = {"grant_type": "client_credentials"}

    response = req.post(url, headers=headers, auth=auth, data=data)
    response.raise_for_status()
    return response.json().get("access_token")

def get_captured_payment(capture_id):
    url =  f'{baseURL}/v2/payments/captures/{capture_id}'
    access = get_paypal_access_token()
    headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access}',
                "Accept": "application/json"
            }
    
    response = req.get(url, headers=headers)

    print(response)

    if response.status_code == 200:
        return response.json()
    else:
        return None
    
# @login_required
# def notifications_view(request):

#     pending_listings = ListingApplication.objects.filter(list_app_status='PENDING').count()
#     pending_users = UserApplication.objects.filter(user_app_status='PENDING').count()
#     pending_reports = Report.objects.filter(report_status='PENDING').count()

#     # Pass data to the template
#     context = {   
#         'pending_listings': pending_listings,
#         'pending_users': pending_users,
#         'pending_reports': pending_reports,
#     }
# 
#     return render(request, 'base.html', context)

@login_required
@user_passes_test(is_admin)
def send_payout(request, payout_id):
    try:
        payout = PayoutRequest.objects.get(payout_id=payout_id)

        transaction = Transaction.objects.get(order_id=payout.order_id)

        capture_id = transaction.transaction_paypal_capture_id

        captured = get_captured_payment(capture_id)

        if captured: 
            cap_amnt = captured['amount']['value']
            # cap_amnt = 100.0

            total_payout = float(cap_amnt) * 0.95

            print(payout.payout_paypal_email)
            print(str(payout.order_id.list_id))
            print(payout.order_id.list_id)

            payout_url = f'{baseURL}/v1/payments/payouts'
            access = get_paypal_access_token()
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access}',
                "Accept": "application/json"
            }

            payout_data = {
                "sender_batch_header": {
                    "sender_batch_id": f"payout_trial-{payout_id}",
                    "email_subject": "You have a payout from Assumemate!"
                },
                "items": [
                    {
                    "recipient_type": "EMAIL",
                    "amount": {
                        "value": total_payout,
                        "currency": "PHP"
                    },
                    "note": "Thanks for using our service!",
                    "sender_item_id": f'list-{payout.order_id.list_id}',
                    "receiver": payout.payout_paypal_email
                    }
                ]
            }

            # print(capture_id)

            response = req.post(payout_url, headers=headers, json=payout_data)

            print(response)

            response.raise_for_status()

            if response.status_code == 201:
                payout.payout_status = 'SENT'
                payout.save()
                print('yawa na kaayu')
                print(response)
                
                transaction = Transaction.objects.create(
                    user_id=request.user,
                    transaction_amount=total_payout,  # Use the amount passed from the request
                    transaction_type='PAYOUT',
                    transaction_date=timezone.now(),
                )

                return JsonResponse({'message': 'Payout sent!'}, status=status.HTTP_200_OK)
            else:
                print(response.raise_for_status())
                return JsonResponse({'error': 'Failed to process payout. PayPal error.'}, status=status.HTTP_400_BAD_REQUEST)
            
        else:
            return JsonResponse({'error': 'Failed to retrieve capture details from PayPal.'}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        print(str(e))
        return JsonResponse({'error': f'An error occured: {e}'}, status=status.HTTP_400_BAD_REQUEST)

    # payout_requests = PayoutRequest.objects.all()  # Fetch all payout requests
    # return render(request, 'base/payout_request_details.html', {'payout_requests': payout_requests})

# def send_refund(request, refund_id):
#     try:
#         refund = RefundRequest.objects.get(refund_id=refund_id)

#         trans = Transaction.objects.get(order_id=refund.order_id)

