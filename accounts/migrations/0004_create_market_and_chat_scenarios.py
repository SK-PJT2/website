from django.db import migrations

def create_market_scenarios(apps, schema_editor):
    User = apps.get_model('accounts', 'CustomUser')
    Product = apps.get_model('market', 'Product')
    Category = apps.get_model('market', 'Category')
    ChatRoom = apps.get_model('chat', 'ChatRoom')

    victim = User.objects.get(username='victim')
    attacker = User.objects.get(username='attacker')
    rich_user = User.objects.get(username='rich_user')
    poor_user = User.objects.get(username='poor_user')

    elec_category = Category.objects.get(slug='electronics')
    
    # 1. Product with negative price (A06)
    p_neg, _ = Product.objects.get_or_create(
        title='[FOR SALE] Free Money!',
        seller=attacker,
        defaults={
            'description': 'Buy this to get 50,000 points!',
            'price': -50000,
            'category': elec_category
        }
    )

    # 2. More Products for variety
    p2, _ = Product.objects.get_or_create(
        title='Used iPhone 12',
        seller=poor_user,
        defaults={
            'description': 'Minor scratches.',
            'price': 400000,
            'category': elec_category
        }
    )

    # 3. Create Bulk Chat Rooms for IDOR (A01)
    # Room ID 2: Rich user buying from victim
    ChatRoom.objects.get_or_create(
        product=Product.objects.get(title='MacBook Pro 16'),
        buyer=rich_user,
        seller=victim
    )

    # Room ID 3: Poor user buying from Attacker (Selling something fake)
    ChatRoom.objects.get_or_create(
        product=p_neg,
        buyer=poor_user,
        seller=attacker
    )

    print("Created more market scenarios and chat rooms for IDOR testing.")

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_create_additional_users'),
        ('market', '0001_initial'),
        ('chat', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_market_scenarios),
    ]
