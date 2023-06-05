from django.contrib import admin
from .models import CustomUser, Clinic, Drug, ClinicMember
from .models import PatientAppointment, PatientAppointment,MedicalProcedure

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Clinic)
admin.site.register(ClinicMember)
admin.site.register(Drug)
admin.site.register(MedicalProcedure)
admin.site.register(PatientAppointment)

