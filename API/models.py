from django.db import models


class User(models.Model):
    login = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=100)
    password = models.CharField(max_length=100)  # Consider using a secure hash here
    AESkey = models.CharField(max_length=512)
    AESkeyIV = models.CharField(max_length=512)
    token = models.CharField(max_length=200)

class Prority(models.Model):
    level = models.IntegerField()
    name = models.CharField(max_length=100)
    uuid = models.CharField(max_length=256, unique=True)
    ownerUser = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )

class Task(models.Model):
    uuid = models.CharField(max_length=256, unique=True)
    name = models.CharField(max_length=100)
    endTime = models.CharField(max_length=200)
    specifiedProrityUUID = models.CharField(max_length=200)
    specifiedUser = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )
class GroupClass(models.Model):
    uuid = models.CharField(max_length=256, unique=True)
    name = models.CharField(max_length=100)
    users = models.CharField(max_length=10000)
    ownerID = models.ForeignKey(
        User,
        on_delete=models.DO_NOTHING
    )

class GroupTask(models.Model):
    uuid = models.CharField(max_length=256, unique=True)
    name = models.CharField(max_length=100)
    endTime = models.CharField(max_length=200)
    specifiedProrityUUID = models.CharField(max_length=200)
    specifiedGroup = models.ForeignKey(
        GroupClass,
        on_delete=models.CASCADE
    )

