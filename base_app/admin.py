from django.contrib import admin
from .models import CustomUser, Clinic, ClinicMember, Prescription, PharmacyInventory
from .models import MedicalProceduresTypes, PatientAppointment, PrescribedMedication

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Clinic)
admin.site.register(ClinicMember)
admin.site.register(MedicalProceduresTypes)
admin.site.register(PatientAppointment)
admin.site.register(PharmacyInventory)
admin.site.register(Prescription)
admin.site.register(PrescribedMedication)



