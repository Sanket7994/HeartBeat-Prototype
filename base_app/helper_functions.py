# IMPORTS
import json
from decimal import Decimal
import stripe, logging
from django.db.models import F
from django.conf import settings
from .views import (
    Clinic,
    ClinicMember,
    PatientAppointment,
    MedicalProceduresTypes,
    Prescription,
)

# Can retrieve collected data from either appointment or prescription unique identifiers
def fetch_master_data(appointment_id=None, prescription_id=None):
    # Creating an empty dictionary
    collection_dict = {}

    if appointment_id is not None:
        appointment = PatientAppointment.objects.filter(appointment_id=appointment_id).values().first()

        if appointment is not None:
            selected_procedures = MedicalProceduresTypes.objects.filter(patientappointment=appointment_id).values()
            prescriptions = Prescription.objects.filter(appointment_id=appointment_id).values()

            prescriptions_data = []
            for prescription in prescriptions:
                prescription_id = prescription["prescription_id"]
                prescription_data = Prescription.objects.filter(prescription_id=prescription_id).values().first()
                prescriptions_data.append(prescription_data)

            staff_id = appointment["relatedRecipient_id"]
            consultant = ClinicMember.objects.filter(staff_id=str(staff_id)).values().first()
            clinic_id = consultant["clinic_name_id"]
            clinic = Clinic.objects.filter(clinic_id=str(clinic_id)).values().first()

            collection_dict["selected_procedures"] = selected_procedures
            collection_dict.update(appointment)
            collection_dict.update(consultant)
            collection_dict.update(clinic)

            prescription_data_dict = {}
            for i, prescription_data in enumerate(prescriptions_data):
                prescription_data_dict[f"prescription_{i+1}"] = prescription_data
                if i == len(prescription_data):
                    break
            collection_dict["prescription_data"] = prescription_data_dict
                
    elif prescription_id is not None:
        prescription = (
            Prescription.objects.filter(prescription_id=prescription_id)
            .values()
            .first()
        )
        if prescription is not None:
            appointment_id = prescription["appointment_id_id"]
            if appointment_id is not None:
                appointment = (
                    PatientAppointment.objects.filter(appointment_id=appointment_id)
                    .values()
                    .first()
                )
                consultant = (
                    ClinicMember.objects.filter(
                        staff_id=appointment["relatedRecipient_id"]
                    )
                    .values()
                    .first()
                )
                clinic = (
                    Clinic.objects.filter(clinic_id=consultant["clinic_name_id"])
                    .values()
                    .first()
                )
                if appointment is not None:
                    if "selected_procedures" not in collection_dict:
                        selected_procedures = MedicalProceduresTypes.objects.filter(
                            patientappointment=appointment_id
                        ).values()
                        collection_dict["selected_procedures"] = selected_procedures

                    if "appointment_id" not in collection_dict:
                        collection_dict.update(appointment)
                        collection_dict.update(consultant)
                        collection_dict.update(clinic)

                    if "prescription_id" not in collection_dict:
                        collection_dict.update(prescription)

    return collection_dict


# Function which creates a payment link from stripe
def create_payment_link(prescription_dict, return_items=False):
    try:
        data = json.loads(prescription_dict["medications_json"])
        
        stripe.api_key = settings.STRIPE_SECRET_KEY

        line_items = [
            {
                "price": str(medicines["stripe_price_id"]),
                "quantity": int(medicines["quantity"]),
            }
            for medicines in data
        ]

        line_items.append(
            {
                "price": str(prescription_dict.get("stripe_appointment_price_id", "")),
                "quantity": 1,
            }
        )
        payment_link_payload = stripe.PaymentLink.create(line_items=line_items)
        payment_url = payment_link_payload["url"]

        if return_items == "line_items":
            return line_items
        elif return_items == "payment_url":
            return payment_url

    except stripe.error.CardError as e:
        logging.error("A payment error occurred: {}".format(e.user_message))
        raise
    except stripe.error.InvalidRequestError:
        logging.error("An invalid request occurred.")
        raise
    except Exception as ex:
        logging.error("Error unrelated to Stripe: {}".format(str(ex)))
        raise


# Decoder 
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        return super().default(o)