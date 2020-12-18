from django.db import models
import uuid

# Create your models here.
class Verification(models.Model):
    user_id = models.IntegerField()
    code = models.UUIDField(default=uuid.uuid4, unique=True)


class ForgotPassword(models.Model):
    user_id = models.IntegerField()
    code = models.UUIDField(default=uuid.uuid4, unique=True)
