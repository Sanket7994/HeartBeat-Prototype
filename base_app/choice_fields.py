from django.db import models
from datetime import time, date, timedelta


class ProcedureChoices(models.TextChoices):
    MEDICAL_EXAMINATION = ("MEDICAL_EXAMINATION", "Medical Examination")
    ROUTINE_CHECK_UP = ("ROUTINE_CHECK_UP", "Routine Check-up")
    RESULT_ANALYSIS = ("RESULT_ANALYSIS", "Result Analysis")
    BLOOD_TESTS = ("BLOOD_TESTS", "Blood Tests")
    X_RAY = ("X_RAY", "X-ray")
    ULTRASOUND = ("ULTRASOUND", "Ultrasound")
    VACCINATIONS = ("VACCINATIONS", "Vaccinations")
    BIOPSY = ("BIOPSY", "Biopsy")
    SURGERY = ("SURGERY", "Surgery")
    PHYSICAL_THERAPY = ("PHYSICAL_THERAPY", "Physical Therapy")
    HEARING_TEST = ("HEARING_TEST", "Hearing Test")
    VISION_TEST = ("VISION_TEST", "Vision Test")
    CARDIAC_STRESS_TEST = ("CARDIAC_STRESS_TEST", "Cardiac Stress Test")
    ORGAN_DONATION = ("ORGAN_DONATION", "Organ Donation")
    CONSULTATION = ("CONSULTATION", "Consultation")
    COLONOSCOPY = ("COLONOSCOPY", "Colonoscopy")
    MRI_SCAN = ("MRI_SCAN", "MRI Scan")
    CT_SCAN = ("CT_SCAN", "CT Scan")
    PAP_SMEAR = ("PAP_SMEAR", "Pap Smear")
    MAMMOGRAM = ("MAMMOGRAM", "Mammogram")
    BONE_DENSITY_TEST = ("BONE_DENSITY_TEST", "Bone Density Test")
    ECG = ("ECG", "Electrocardiogram (ECG or EKG)")
    ENDOSCOPY = ("ENDOSCOPY", "Endoscopy")
    ALLERGY_TESTING = ("ALLERGY_TESTING", "Allergy Testing")
    SPIROMETRY = ("SPIROMETRY", "Spirometry (Lung Function Test)")
    STRESS_TEST = ("STRESS_TEST", "Stress Test (Exercise Tolerance Test)")
    HOLTER_MONITOR = ("HOLTER_MONITOR", "Holter Monitor (24-hour ECG)")
    SLEEP_STUDY = ("SLEEP_STUDY", "Sleep Study (Polysomnography)")
    GASTROSCOPY = ("GASTROSCOPY", "Gastroscopy")
    CARDIAC_CATHETERIZATION = ("CARDIAC_CATHETERIZATION", "Cardiac Catheterization")
    SKIN_BIOPSY = ("SKIN_BIOPSY", "Skin Biopsy")
    CERVICAL_BIOPSY = ("CERVICAL_BIOPSY", "Cervical Biopsy")
    GENETIC_TESTING = ("GENETIC_TESTING", "Genetic Testing")
    LUMBAR_PUNCTURE = ("LUMBAR_PUNCTURE", "Lumbar Puncture (Spinal Tap)")
    STOOL_TEST = ("STOOL_TEST", "Stool Test (Fecal Occult Blood Test)")
    TREADMILL_TEST = ("TREADMILL_TEST", "Treadmill Test")
    DOPPLER_ULTRASOUND = ("DOPPLER_ULTRASOUND", "Doppler Ultrasound")
    NUCLEAR_STRESS_TEST = ("NUCLEAR_STRESS_TEST", "Nuclear Stress Test")
    OTHER = ("OTHER", "Other")


class StatusCode(models.TextChoices):
    APPROVED = ("APPROVED", "Approved")
    PENDING = ("PENDING", "Pending")
    CANCELLED = ("CANCELLED", "Cancelled")


class Country(models.TextChoices):
    UK = ("UK", "UNITED KINGDOM")
    IN = ("IN", "INDIA")
    US = ("US", "UNITED STATES OF AMERICA")
    ES = ("ES", "SPAIN")
    CN = ("CN", "CHINA")


class EmployeeStatusCode(models.TextChoices):
    ACTIVE = ("ACTIVE", "Active")
    INACTIVATE = ("INACTIVATE", "Inactivate")
    ON_NOTICE_PERIOD = ("ON_NOTICE_PERIOD", "On Notice Period")


class StaffDesignation(models.TextChoices):
    IVF_COORDINATOR = "IVF_COORDINATOR", "IVF Coordinator"
    DONOR_COORDINATOR = "DONOR_COORDINATOR", "Donor Coordinator"
    RECEPTIONIST = "RECEPTIONIST", "Receptionist"
    ADMIN = "ADMIN", "Admin"
    DOCTOR_PHYSICIST = "DOCTOR_PHYSICIST", "Doctor/Physicist"
    EMBRYOLOGY = "EMBRYOLOGY", "Embryology"
    NURSE = "NURSE", "Nurse"
    LABORATORY = "LABORATORY", "Laboratory"
    PSYCHOLOGIST_COUNSELLOR = "PSYCHOLOGIST_COUNSELLOR", "Psychologist/Counsellor"


class Shift_type(models.TextChoices):
    GENERAL_SHIFT = (
        "General Shift 9AM - 6PM",
        f"{time(9, 0).strftime('%I:%M %p')} - {time(18, 0).strftime('%I:%M %p')}",
    )
    FLEX_SHIFT_1 = (
        "Flex Shift 10AM - 2PM",
        f"{time(10, 0).strftime('%I:%M %p')} - {time(14, 0).strftime('%I:%M %p')}",
    )
    FLEX_SHIFT_2 = (
        "Flex Shift 3PM - 7PM",
        f"{time(15, 0).strftime('%I:%M %p')} - {time(19, 0).strftime('%I:%M %p')}",
    )
    FRONT_LINE_SHIFT_1 = (
        "Front Line Shift 7AM - 7PM",
        f"{time(7, 0).strftime('%I:%M %p')} - {time(19, 0).strftime('%I:%M %p')}",
    )
    FRONT_LINE_SHIFT_2 = (
        "Front Line Shift 7PM - 7AM",
        f"{time(19, 0).strftime('%I:%M %p')} - {time(7, 0).strftime('%I:%M %p')}",
    )


class Gender(models.TextChoices):
    MALE = "MALE", "Male"
    FEMALE = "FEMALE", "Female"
    UNDISCLOSED = "UNDISCLOSED", "Undisclosed"


class TaskStatusCode(models.TextChoices):
    COMPLETED = ("COMPLETED", "Completed")
    PENDING = ("PENDING", "Pending")
    POSTPONED = ("POSTPONED", "Postponed")
    OVERDUE = ("OVERDUE", "Overdue")


class SetPriority(models.TextChoices):
    HIGH = ("HIGH", "High")
    MID = ("MID", "Mid")
    LOW = ("LOW", "Low")


class TaskType(models.TextChoices):
    GROUP = ("GROUP", "Group")
    INDIVIDUAL = ("INDIVIDUAL", "Individual")


class LabelChoices(models.TextChoices):
    PERSONAL = ("PERSONAL", "Personal")
    WORK = ("WORK", "Work")
    EVENT = ("EVENT", "Event")
    REMINDER = ("REMINDER", "Reminder")
    APPOINTMENT = ("APPOINTMENT", "Appointment")
    IMPORTANT = ("IMPORTANT", "Important")


class DosageType(models.TextChoices):
    ORAL = "ORAL", "Oral"
    OPHTHALMIC = "OPHTHALMIC", "Ophthalmic"
    INHALATION = "INHALATION", "Inhalation"
    INJECTION = "INJECTION", "Injection"
    TOPICAL = "TOPICAL", "Topical"
    OTHER = "OTHER", "Other"


class GeneralDrugClass(models.TextChoices):
    ANALGESICS = (
        "ANALGESICS: Used for headaches, muscle pain, toothaches, menstrual pain",
        "ANALGESICS",
    )
    ANTACIDS = (
        "ANTACIDS: Used for heartburn, indigestion, acid reflux",
        "ANTACIDS",
    )
    ANTIHISTAMINES = (
        "ANTIHISTAMINES: Used for allergies, itchy skin or eyes, sneezing, runny nose",
        "ANTIHISTAMINES",
    )
    COUGH_AND_COLD = (
        "COUGH AND COLD: Used for cough relief, nasal congestion, sore throat",
        "COUGH_AND_COLD",
    )
    TOPICAL_ANALGESICS = (
        "TOPICAL ANALGESICS: Used for muscle aches and strains, joint pain, minor injuries",
        "TOPICAL_ANALGESICS",
    )
    DERMATOLOGICAL = (
        "DERMATOLOGICAL: Used for acne treatment, eczema or dermatitis management, fungal infections",
        "DERMATOLOGICAL",
    )
    ORAL_CONTRACEPTIVES = (
        "ORAL CONTRACEPTIVES: Used for pregnancy prevention",
        "ORAL_CONTRACEPTIVES",
    )
    OPHTHALMIC = (
        "OPHTHALMIC: Used for eye infections, dry eyes, allergic conjunctivitis",
        "OPHTHALMIC",
    )
    TEST_KITS = (
        "TEST KITS: Used as diagnostic tools to detect and analyze various medical conditions or substances.",
        "TEST_KITS",
    )
    ANTIPYRETICS = ("ANTIPYRETICS: Used to reduce fever", "ANTIPYRETICS")
    ANTIDIARRHEALS = ("ANTIDIARRHEALS: Used for diarrhea relief", "ANTIDIARRHEALS")
    OTHER = ("Other", "OTHER")


class UnitType(models.TextChoices):
    SINGLE_UNIT = "SINGLE_UNIT", "Single Unit"
    PACK_OF_10 = "PACK_OF_10", "Pack of 10"
    PACK_OF_50 = "PACK_OF_50", "Pack of 50"


class DosingFrequency(models.TextChoices):
    ONCE_A_DAY = "ONCE_A_DAY", "Once a day"
    TWICE_A_DAY = "TWICE_A_DAY", "Twice a day"
    THRICE_A_DAY = "THRICE_A_DAY", "Thrice a day"
    FLEXIBLE = "FLEXIBLE", "Flexible timings"


class BudgetPeriodType(models.TextChoices):
    YEARLY = "YEARLY", "Yearly"
    QUARTERLY = "QUARTERLY", "Quarterly"
    MONTHLY = "MONTHLY", "Monthly"



