# Download the helper library from https://www.twilio.com/docs/python/install
from school import settings
from twilio.rest import Client

# Set environment variables for your credentials
# Read more at http://twil.io/secure


# send sms notification to patient
def send_sms_notification_patient(patient, staff_member):
    relatedRecipient_firstName = staff_member.get("first_name")
    relatedRecipient_lastName = staff_member.get("last_name")
    patientNumber = "".join(list(patient.get("contact_number")))

    account_sid = settings.TWILIO_ACCOUNT_SID
    auth_token = settings.TWILIO_AUTH_TOKEN
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        messaging_service_sid=settings.TWILIO_MESSAGING_SERVICE_SID,
        body=f"""
Hi {patient.get('patient_first_name')}, 

An appointment has been successfully setup with Dr.{relatedRecipient_firstName} {relatedRecipient_lastName} on {patient.get('appointment_date')} at assigned time slot of {patient.get('appointment_slot')}. 

If you are unable to make this appointment or would like to change your appointment to a different date or time reply to this email.

Thank you for your business,

Kind regards,
TestProject Support Team
""",
        from_="+13614597582",
        to=patientNumber,
    )
    print(message.sid)


# send sms notification to staff_member
def send_sms_notification_staff_member(staff_member):
    relatedRecipient_firstName = staff_member.get("first_name")
    staff_memberNumber = "".join(list(staff_member.get("contact_number")))
    print(staff_memberNumber)

    account_sid = settings.TWILIO_ACCOUNT_SID
    auth_token = settings.TWILIO_AUTH_TOKEN
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        messaging_service_sid=settings.TWILIO_MESSAGING_SERVICE_SID,
        body=f"""
Hi {relatedRecipient_firstName}, 

An appointment has been successfully setup with the client. 
please check the dashboard for more information.

Kind regards,
project Support Team
""",
        from_="+13614597582",
        to=staff_memberNumber,
    )
    print(message.sid)
