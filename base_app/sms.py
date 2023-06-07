from sendsms.message import SmsMessage


def send_sms_notification(patientNumber, recipientNumber):
    auth_sms_sender = '+918500449007'
    message_to_patient = SmsMessage(body='lolcats make me hungry', from_phone=auth_sms_sender, to=patientNumber)
    message_to_recipient = SmsMessage(body='lolcats make me hungry', from_phone=auth_sms_sender, to=recipientNumber)
    message_to_patient.send()
    message_to_recipient.send()
    #'+41791111111'