# Generated by Django 5.1.1 on 2024-10-04 05:06

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0008_alter_customuser_email_alter_otp_user_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.DeleteModel(
            name='Verification',
        ),
    ]
