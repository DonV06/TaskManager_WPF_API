from django.db import models

class User(models.Model):
    login = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=100)
    password = models.CharField(max_length=100)  # Consider using a secure hash here
    AESkey = models.CharField(max_length=512)
    AESkeyIV = models.CharField(max_length=512)
    token = models.CharField(max_length=200)
