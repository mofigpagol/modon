# Generated by Django 5.0 on 2024-08-01 07:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad', '0007_companybanner'),
    ]

    operations = [
        migrations.AddField(
            model_name='navbarlink',
            name='navbar_type',
            field=models.CharField(choices=[('CATEGORY', 'Category'), ('CUSTOM', 'Custom')], default='CATEGORY', max_length=10),
        ),
    ]
