# IMPORTS
import stripe, logging
from django.db.models import F
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from .views import (
    Clinic,
    ClinicMember,
    PatientAppointment,
    MedicalProceduresTypes,
    PrescribedMedication,
    Prescription,
)


# Function which collects all the information related to a specified prescription as id
def fetch_prescription_data(prescription_id):
    prescription = (
        Prescription.objects.filter(prescription_id=prescription_id).values().first()
    )
    prescribed_meds = (
        PrescribedMedication.objects.filter(for_prescription_id=prescription_id)
        .annotate(
            medicine_name=F("medicine__drug_name"),
            medicine_purpose=F("medicine__drug_class"),
            stripe_medicine_id=F("medicine__stripe_product_id"),
            stripe_price_id=F("medicine__stripe_price_id"),
        )
        .values()
    )
    appointment = (
        PatientAppointment.objects.filter(
            appointment_id=prescription["appointment_id_id"]
        )
        .values()
        .first()
    )
    selected_procedures = MedicalProceduresTypes.objects.filter(
        patientappointment=appointment["appointment_id"]
    ).values()
    staff = (
        ClinicMember.objects.filter(staff_id=str(appointment["relatedRecipient_id"]))
        .values()
        .first()
    )
    clinic = (
        Clinic.objects.filter(clinic_id=str(staff["clinic_name_id"])).values().first()
    )

    prescription_dict = {
        **prescription,
        "prescribed_meds": prescribed_meds,
        **appointment,
        "selected_procedures": selected_procedures,
        **staff,
        **clinic,
    }

    keys = [
        "prescription_id",
        "stripe_appointment_service_id",
        "stripe_appointment_price_id",
        "appointment_fee",
        "med_bill_amount",
        "coupon_discount",
        "grand_total",
        "description",
        "approval_status",
        "created_at",
        "prescribed_meds",
        "appointment_id",
        "patient_first_name",
        "patient_first_name",
        "patient_last_name",
        "patient_gender",
        "date_of_birth",
        "patient_age",
        "patient_email",
        "patient_contact_number",
        "recurring_patient",
        "appointment_date",
        "appointment_slot",
        "appointment_status",
        "selected_procedures",
        "staff_first_name",
        "staff_last_name",
        "staff_designation",
        "staff_email",
        "staff_contact_number",
        "clinic_name",
        "clinic_logo",
        "clinic_contact_number",
        "clinic_address",
        "clinic_city",
        "clinic_zipcode",
        "clinic_country",
        "clinic_email",
    ]

    if keys is not None:
        prescription_dict = {
            key: prescription_dict[key] for key in keys if key in prescription_dict
        }
    return prescription_dict


# Function which creates a payment link from stripe
def create_payment_link(prescription_dict):
    try:
        stripe.api_key = settings.STRIPE_SECRET_KEY

        line_items = [
            {
                "price": str(med_data["stripe_price_id"]),
                "quantity": int(med_data["quantity"]),
            }
            for med_data in prescription_dict["prescribed_meds"]
        ]

        line_items.append(
            {
                "price": str(prescription_dict.get("stripe_appointment_price_id", "")),
                "quantity": 1,
            }
        )
        # Allowing coupon codes at the time of checkout
        print(line_items)
        return line_items

        # payment_link_payload = stripe.PaymentLink.create(line_items=line_items)
        # payment_url = payment_link_payload["url"]
        # # Payment link created
        # return payment_url
    # Error case handling
    except stripe.error.CardError as e:
        logging.error("A payment error occurred: {}".format(e.user_message))
    except stripe.error.InvalidRequestError:
        logging.error("An invalid request occurred.")
    except Exception as ex:
        logging.error("Error unrelated to Stripe: {}".format(str(ex)))
