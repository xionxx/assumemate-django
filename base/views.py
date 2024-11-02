from io import BytesIO
import os
from dotenv import load_dotenv
import random, string, cloudinary, base64
from django.views.decorators.csrf import csrf_protect
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from django.db import IntegrityError
from smtplib import SMTPConnectError, SMTPException
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
from django.db.models import Q, Count
from .permissions import IsAdminUser
from .models import ListingApplication, PasswordResetToken, UserApplication, UserProfile, Report, Listing, PromoteListing
from rest_framework import viewsets, status, permissions
from django.contrib.auth.hashers import check_password
from django.template.loader import render_to_string
from rest_framework.response import Response
from django.db.models.functions import ExtractMonth
from django.core.files.base import ContentFile
from django.contrib.auth import login as login, authenticate, logout, get_user_model, update_session_auth_hash

load_dotenv()
UserModel = get_user_model()

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
                                                 user_prof_pic=image_json, user_id=user)
            
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
        return redirect('admin_acc_create')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        print(email)
        print(password)

        user = authenticate(request, email=email, password=password)
        print(user)
        if user is not None:
            login(request, user)
            return redirect('admin_acc_create')
        else:
            print("Authentication failed")
            return JsonResponse({'auth_failed': 'Incorrect email or password'})
        
    return render(request, 'base/login.html')

def edit_profile(request):
    profile = request.user.profile
    context = {'user': request.user, 'profile': profile}
    return render(request, 'base/edit_profile.html', context)

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

# @login_required(login_url='user_login')
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

def pending_accounts_view(request):
    pending_applications = UserApplication.objects.filter(user_app_status='PENDING')
    pending_assumptors = pending_applications.filter(user_prof_id__user_id__is_assumptor=True)
    pending_assumees = pending_applications.filter(user_prof_id__user_id__is_assumee=True)
    context = {
        'pending_assumptors': pending_assumptors,
        'pending_assumees': pending_assumees,
    }
    
    return render(request, 'base/rev_pending_users.html', context)

def assumemate_rev_report_users(request):
    reports = Report.objects.filter(report_status='PENDING')
    context = {
        'reports': reports,
    }
    return render(request, 'base/rev_reported_users.html', context)

def user_detail_view(request, user_id):
    user = get_object_or_404(UserModel, pk=user_id)
    return render(request, 'base/user_detail.html', {'user': user})

def assumemate_users(request):
    status = request.GET.get('status', 'all')  # Get the selected category
    application = UserApplication.objects.select_related('user_prof_id', 'user_app_reviewer_id')

    # Filter based on status
    if status == 'Assumptors':
        application = application.filter(user_prof_id__user_id__is_assumptor=True)
    elif status == 'Assumees':
        application = application.filter(user_prof_id__user_id__is_assumee=True)
    elif status == 'Suspend':
        application = application.none()  # Assuming no logic for Suspend, modify as needed
    else:
        application = application.filter(Q(user_prof_id__user_id__is_assumptor=True) | Q(user_prof_id__user_id__is_assumee=True))

    assumptor_count = UserModel.objects.filter(is_assumptor=True).count()
    assumee_count = UserModel.objects.filter(is_assumee=True).count()

    total_user = assumptor_count + assumee_count

    context = {
        'assumptor_count': assumptor_count,
        'assumee_count': assumee_count,
        'total_user' : total_user,
        'application' : application
    }

    return render(request, 'base/users.html', context)

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
    house_and_lot_count = category_count_dict.get('House and Lot', 0)
    cars_count = category_count_dict.get('Cars', 0)
    motorcycles_count = category_count_dict.get('Motorcycles', 0)

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
        
    }

    return render(request, 'base/listing.html', context)

def users_view_details(request, user_id):
    current_date = timezone.now()
    print(f"Requested user_id: {user_id}")  # Debugging line
    user_profile = get_object_or_404(UserProfile, user_prof_id=user_id)
    user_details = UserApplication.objects.select_related('user_prof_id', 'user_app_reviewer_id').filter(user_prof_id=user_profile).first()
    
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

def accept_report(request, report_id):
    report = get_object_or_404(Report, report_id=report_id)
    report.report_status = 'APPROVED'
    report.updated_at = timezone.now()
    report.save()
    messages.success(request, 'Report has been accepted.')
    return redirect('assumemate_rev_report_users')  

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

def report_detail_view(request, report_id):
    userreport = get_object_or_404(Report, pk=report_id)
    return render(request, 'base/report_detail.html', {'userreport': userreport})

def platform_report(request):
    # Count the different user types
    assumptors_count = UserModel.objects.filter(is_assumptor=True).count()
    assumees_count = UserModel.objects.filter(is_assumee=True).count()
    total_users_count = UserModel.objects.filter(Q(is_assumptor=True) | Q(is_assumee=True)).count()
    admins_count = UserModel.objects.filter(is_superuser=True).count()
    reviewers_count = UserModel.objects.filter(is_reviewer=True).count()
    active_accounts_count = UserModel.objects.filter(Q(is_active=True) & (Q(is_assumptor=True) | Q(is_assumee=True))).count()
    inactive_accounts_count = UserModel.objects.filter(Q(is_active=False) & (Q(is_assumptor=True) | Q(is_assumee=True))).count()
    promoted_listings_count = PromoteListing.objects.count()

    # Prepare data for user growth chart
    user_growth_data = UserModel.objects.annotate(month=ExtractMonth('date_joined')) \
        .values('month') \
        .annotate(count=Count('id')) \
        .order_by('month')

    # Prepare data for Assumptors and Assumees per month
    user_type_data = UserModel.objects.annotate(month=ExtractMonth('date_joined')) \
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

    # Prepare data for the first user growth chart
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
    }
    return render(request, 'base/reports.html', context)

def listing_view_details(request, user_id, list_id):
    current_date = timezone.now()

    # Debug: Print the user_id and list_id being passed
    print(f"Requested listing user_id: {user_id}")
    print(f"Requested listing list_id: {list_id}")

    # Fetch the specific listing or return 404
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

def assumemate_rev_pending_list(request):
    pending_listings = ListingApplication.objects.filter(list_app_status='PENDING').select_related('list_id')
    
    context = {
        'pending_listings': pending_listings,
    }
    
    return render(request, 'base/rev_pending_listing.html', context)

@login_required(login_url='user_login')
def logout_user(request):
    if request.user.is_authenticated:
        logout(request)
        return redirect(user_login)

def usertype_is_active(request, admin_id, status):

    user = UserModel.objects.get(id=admin_id)

    user.is_active = status
    user.save()
    
    # Redirect based on user type
    if user.is_staff:  # If the user is an Admin
        return redirect('admin_acc_list')  # Redirect to admin account list
    elif user.is_reviewer:  # If the user is a Reviewer
        return redirect('reviewer_acc_list') 

def approve_user(request, id):
    try:
        user = UserApplication.objects.get(user_prof_id=id)
        user.user_app_status = 'APPROVED'
        user.save()
        return
    except:
        return
    
def reject_user(request, id):
    try:
        user = UserApplication.objects.get(user_prof_id=id)
        user.user_app_status = 'REJECTED'
        user.save()
        return
    except:
        return 

###### render views ######.
def base(request):
    context = {}
    return render(request, "base/home.html", context)

# @user_passes_test(is_admin)
# @login_required(login_url='user_login')
def admin_acc_create(request):
    context = {'nav': 'admin', 'user_type': 'Admin'}
    return render(request, 'base/add_upperuser.html', context)

def admin_acc_list(request):
    admin = UserModel.objects.filter(is_staff=True)
    context = {'admin': admin, 'nav': 'admin'}
    # context = {'nav': 'admin'}
    return render(request, 'base/admin_list.html', context)

def user_application_list(request):
    user_application = UserModel.objects.filter(is_staff=True)
    context = {'users': user_application, 'nav': 'user'}
    # context = {'nav': 'admin'}
    return render(request, 'base/users_list.html', context)

def reviewer_acc_list(request):
    reviewer = UserModel.objects.filter(is_reviewer=True)
    context = {'reviewer': reviewer, 'nav': 'reviewer'}
    # context = {'nav': 'admin'}
    return render(request, 'base/reviewer_list.html', context)

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