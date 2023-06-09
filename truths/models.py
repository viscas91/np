from django.db import models

class UserConnection(models.Model):
    ip = models.CharField(max_length=255)
    network = models.CharField(max_length=255, null=True)
    version = models.CharField(max_length=10, null=True)
    city = models.CharField(max_length=255, null=True)
    region = models.CharField(max_length=255, null=True)
    region_code = models.CharField(max_length=10, null=True)
    country = models.CharField(max_length=10, null=True)
    country_name = models.CharField(max_length=255, null=True)
    country_code = models.CharField(max_length=10, null=True)
    country_code_iso3 = models.CharField(max_length=10, null=True)
    country_capital = models.CharField(max_length=255, null=True)
    country_tld = models.CharField(max_length=10, null=True)
    continent_code = models.CharField(max_length=10, null=True)
    in_eu = models.BooleanField(null=True)
    postal = models.CharField(max_length=10, null=True)
    latitude = models.FloatField(null=True)
    longitude = models.FloatField(null=True)
    timezone = models.CharField(max_length=255, null=True)
    utc_offset = models.CharField(max_length=10, null=True)
    country_calling_code = models.CharField(max_length=10, null=True)
    currency = models.CharField(max_length=10, null=True)
    currency_name = models.CharField(max_length=255, null=True)
    languages = models.CharField(max_length=255, null=True)
    country_area = models.FloatField(null=True)
    country_population = models.BigIntegerField(null=True)
    asn = models.CharField(max_length=255, null=True)
    org = models.CharField(max_length=255, null=True)
    device_info = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f'{self.ip} - {self.created_at}'