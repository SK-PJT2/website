from django.db import migrations

def create_board_scenarios(apps, schema_editor):
    User = apps.get_model('accounts', 'CustomUser')
    Post = apps.get_model('board', 'Post')
    Question = apps.get_model('board', 'Question')
    
    admin = User.objects.get(username='admin')
    victim = User.objects.get(username='victim')
    attacker = User.objects.get(username='attacker')

    # 1. Sensitive Post (Target for SQL Injection A05)
    Post.objects.get_or_create(
        title='[CONFIDENTIAL] 2025 Financial Report',
        author=admin,
        defaults={
            'content': 'Total Revenue: 500,000,000 Points. Internal use only.'
        }
    )

    # 2. Questions with Bounties (Potential manipulation point)
    Question.objects.get_or_create(
        title='How to secure a Django app?',
        author=victim,
        defaults={
            'content': 'I am worried about OWASP Top 10.',
            'bounty': 10000
        }
    )

    Question.objects.get_or_create(
        title='Is my password safe?',
        author=attacker,
        defaults={
            'content': 'My secondary password is very secret.',
            'bounty': 0
        }
    )

    print("Created board scenarios (Confidential posts, Questions with bounties).")

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_create_market_and_chat_scenarios'),
        ('board', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_board_scenarios),
    ]
