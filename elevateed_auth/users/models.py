from django.db import models

class Users(models.Model):
    id = models.UUIDField(primary_key=True)
    full_name = models.CharField(max_length=100)
    email = models.CharField(unique=True, max_length=255)
    password = models.TextField()
    role = models.TextField()  # This field type is a guess.
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False  # Django does not manage this table
        db_table = 'users'


