@property
def get_age(self):
    if self.date_of_birth is None:
        return None
    age = timezone.now().date() - self.date_of_birth
    return int((age.days) / 365.25)