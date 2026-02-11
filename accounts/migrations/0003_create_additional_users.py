from django.db import migrations
from django.contrib.auth.hashers import make_password

def create_more_users(apps, schema_editor):
    User = apps.get_model('accounts', 'CustomUser')
    
    # 1. Rich User (Points for manipulation tests)
    User.objects.get_or_create(
        username='rich_user',
        defaults={
            'email': 'rich@example.com',
            'password': make_password('rich123'),
            'nickname': 'RichGuy',
            'points': 1000000,
            'secondary_password': 'gold_standard_pw'
        }
    )

    # 2. Poor User
    User.objects.get_or_create(
        username='poor_user',
        defaults={
            'email': 'poor@example.com',
            'password': make_password('poor123'),
            'nickname': 'NeedsPoints',
            'points': 500,
            'secondary_password': '1' 
        }
    )

    # 3. Suspicious User (to be used in various scenarios)
    User.objects.get_or_create(
        username='suspicious_user',
        defaults={
            'email': 'sus@example.com',
            'password': make_password('sus123'),
            'nickname': 'SusPerson',
            'secondary_password': 'password'
        }
    )
    print("Created additional users: rich_user, poor_user, suspicious_user")

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_create_test_data'),
    ]

    operations = [
        migrations.RunPython(create_more_users),
    ]
