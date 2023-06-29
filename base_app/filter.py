# Filter and search for views

def filter_queryset(queryset, filter_fields):
    for field, value in filter_fields.items():
        if value:
            queryset = queryset.filter(**{field: value})
    return queryset


def clean_data(data):
    cleaned_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            cleaned_data[key] = clean_data(value)  # Recursively clean nested dictionaries
        else:
            if value == "null":
                cleaned_data[key] = None
            elif value == "false":
                cleaned_data[key] = False
            elif value == "true":
                cleaned_data[key] = True
            else:
                cleaned_data[key] = value
    return cleaned_data
