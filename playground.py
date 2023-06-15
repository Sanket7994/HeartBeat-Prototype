import datetime as dt


HOUR_CHOICES = [(dt.time(hour=x), '{:02d}:00'.format(x)) for x in range(7, 13)]


print(type(HOUR_CHOICES[0]))
print(HOUR_CHOICES[0])