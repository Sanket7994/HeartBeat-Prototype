from school import settings
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags


#### Email seeding functions #####


# Email notification after signup
def send_email_notification(recipient_list, fetched_activation_OTP):
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Update Notification"
    html_body = f"""
<div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
  <div style="margin:50px auto;width:70%;padding:20px 0">
    <div style="border-bottom:1px solid #eee;display:flex;align-items:center;">
      <div style="transform: rotate(-90deg);margin-right:10px;">
        <img src="../media/SHIPSY_LOGO_BIRD_BLUE.png" alt="Brand Logo" width="50">
      </div>
      <a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600;white-space: nowrap;">TestProject</a>
    </div>
    <p style="font-size:1.1em">Hi,</p>
    <p>Thank you for choosing TestProject. Use the following OTP to complete your Sign Up procedures. OTP is valid for 10 minutes</p>
    <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">{fetched_activation_OTP}</h2>
    <p style="font-size:0.9em;">Regards,<br />TestProject</p>
    <hr style="border:none;border-top:1px solid #eee" />
    <div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300">
      <p>TestProject Inc</p>
      <p>Madrid</p>
      <p></p>
    </div>
  </div>
</div>
    """
    send_mail(subject, html_body, email_from, recipient_list)

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
    TestProject Support Team
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
TestProject Support Team
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
TestProject Support Team

"""
    send_mail(subject, message, email_from, recipient_list)

    return True


# Email notification after signup
def send_email_notification_to_staff(staff_member):
    relatedRecipient_email = staff_member.get("email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Appointment update Notification"
    message = f"""
Hi {staff_member.get('staff_first_name')}, 

An appointment has been successfully setup with the client. 
please check the dashboard for more information.

Kind regards,
TestProject Support Team
"""
    send_mail(subject, message, email_from, [relatedRecipient_email])

    return True


# Email notification after signup
def send_email_notification_to_patient(patient, staff_member):
    relatedRecipient_firstName = staff_member.get("staff_first_name")
    relatedRecipient_lastName = staff_member.get("staff_last_name")
    patient_email = patient.get("email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Appointment update Notification"
    message = f"""
Hi {patient.get('patient_first_name')}, 

An appointment has been successfully setup with Dr.{relatedRecipient_firstName} {relatedRecipient_lastName} on {patient.get('appointment_date')} at assigned time slot of {patient.get('appointment_slot')}. 

Our Team will be waiting for your arrival. Thanks for choosing us.

Kind regards,
TestProject Support Team
"""
    send_mail(subject, message, email_from, [patient_email])

    return True


# Send payment link to client email address 
def send_pay_link_via_email(client, pay_link):
    client_email = client.get("patient_email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Pending Payment Notification Email"
    
    # Render the HTML template with the button
    html_message = render_to_string(
        "../templates/pay_link_email.html",
        {"client": client, "pay_link": pay_link}
    )
    
    # Extract the plain text content from the HTML
    plain_message = strip_tags(html_message)
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=email_from,
        recipient_list=[client_email],
        html_message=html_message
    )
    
    return True


# Send payment link to client email address 
def send_successful_purchase_email(client, pay_link):
    client_email = client.get("patient_email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Pending Payment Notification Email"
    
    # Render the HTML template with the button
    html_message = render_to_string(
        "../templates/pay_link_email.html",
        {"client": client, "pay_link": pay_link}
    )
    
    # Extract the plain text content from the HTML
    plain_message = strip_tags(html_message)
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=email_from,
        recipient_list=[client_email],
        html_message=html_message
    )
    
    return True



