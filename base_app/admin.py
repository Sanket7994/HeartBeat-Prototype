from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Clinic)
admin.site.register(ClinicMember)
admin.site.register(ClientDataCollectionPool)
admin.site.register(Prescription)
admin.site.register(PharmacyInventory)
admin.site.register(MedicalProceduresTypes)
admin.site.register(PatientAppointment)
admin.site.register(ClientServiceFeedback)
admin.site.register(PurchaseOrder)
admin.site.register(TaskAssignmentManager)
admin.site.register(PersonalJournal)
admin.site.register(POPayment)




