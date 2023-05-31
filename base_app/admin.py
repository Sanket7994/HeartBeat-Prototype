from django.contrib import admin
from .models import CustomUser, Clinic, Drug, ClinicMember, PatientAppointment

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Clinic)
admin.site.register(ClinicMember)
admin.site.register(Drug)
admin.site.register(PatientAppointment)

