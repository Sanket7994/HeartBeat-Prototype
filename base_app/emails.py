from school import settings
from rest_framework.response import Response
from django.core.mail import send_mail


#### Email seeding functions #####


# Email notification after signup
def send_email_notification(recipient_list):
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Activation Notification"
    message = "Your account has been activated"
    send_mail(subject, message, email_from, recipient_list)

    return True


# Email notification If user changes Profile information
def send_user_profile_update_notification(recipient_list):
    
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Update Notification"
    message = """
    Hi, 
    
    As per request we have updated your account information. 
    Please check your account and If you haven`t updated any information Please contact our Customer Support. 
     
    Thanks! Regards.
    Team HeartBeat
    """
    send_mail(subject, message, email_from, recipient_list)

    return True


# Password reset email
def send_forget_password_mail(recipient_list, uid, token):
    reset_password_link = f"http://127.0.0.1:5500/Change-Password/change_password_page.html?uid={uid}&token={token}"
    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(
        "Account Password Reset Notification",
        f"""
Hi {recipient_list.get('first_name')}, 

There was a request to change your password! 
Please click this link to change your password: {reset_password_link}

Kind regards,
Team HeartBeat
""",
        email_from,
        [recipient_list],
        fail_silently=False,
    )
    return True


# Email notification If user changes Profile information
def send_user_profile_delete_notification(recipient_list):
    
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Deletion Notification"
    message = f"""
    
Dear {recipient_list.get('first_name')},

We regret to inform you that your account with HeartBeat has been deleted as per your request. This action is irreversible, and all associated data and information have been permanently removed from our systems.
    
If you have any further queries or require assistance, please don't hesitate to reach out to our support team at {email_from}.
Thank you for being a part of HeartBeat. We appreciate your past support and wish you all the best in your future endeavors.

Kind regards,
Team HeartBeat

"""
    send_mail(subject, message, email_from, recipient_list)

    return True
