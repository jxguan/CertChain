from django.db import models

class Transaction(models.Model):
  txn_id = models.TextField(null=False, unique=True)
  document = models.TextField(null=False)