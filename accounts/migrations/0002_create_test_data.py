from django.db import migrations
from django.contrib.auth import get_user_model
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

def create_test_data(apps, schema_editor):
    User = apps.get_model('accounts', 'CustomUser')
    Post = apps.get_model('board', 'Post')
    Product = apps.get_model('market', 'Product')
    Category = apps.get_model('market', 'Category')
    ChatRoom = apps.get_model('chat', 'ChatRoom')

    # 1. Create Users
    # - admin (Superuser)
    # - victim (Seller)
    # - attacker (Buyer/Attacker)
    
    # We use create_superuser/create_user equivalent logic manually because managers might not be available
    # But for migrations, using the model manager is sometimes tricky. 
    # Here we assume standard manager behavior or just create objects.
    # However, for passwords, we need to hash them properly if we want them to work.
    # OR we can just set them using set_password if we could access the real model, 
    # but inside migrations we only get a serialized version.
    # So we used make_password from django.contrib.auth.hashers
    
    from django.contrib.auth.hashers import make_password

    if not User.objects.filter(username='admin').exists():
        User.objects.create(
            username='admin',
            email='admin@example.com',
            password=make_password('admin123'),
            is_staff=True,
            is_superuser=True,
            nickname='AdminUser'
        )
        print("Created superuser: admin/admin123")

    victim, _ = User.objects.get_or_create(
        username='victim',
        defaults={
            'email': 'victim@example.com',
            'password': make_password('victim123'),
            'nickname': 'VictimSeller',
            'secondary_password': 'secure_secondary_password' # A04: Plain text check
        }
    )
    
    attacker, _ = User.objects.get_or_create(
        username='attacker',
        defaults={
            'email': 'attacker@example.com',
            'password': make_password('attacker123'),
            'nickname': 'AttackerUser',
            'secondary_password': 'hacker_secret' 
        }
    )
    print("Created users: victim/victim123, attacker/attacker123")
    
    # 2. Create Category
    # Use slug for lookup to avoid unique constraint violations
    elec_category, _ = Category.objects.get_or_create(
        slug='electronics',
        defaults={'name': 'Electronics'}
    )

    # 3. Create Product (by Victim)
    product, _ = Product.objects.get_or_create(
        title='MacBook Pro 16',
        seller=victim,
        defaults={
            'description': 'Almost new, very cheap.',
            'price': 1500000,
            'category': elec_category
        }
    )
    
    # 3.1 Create Product (by Attacker for Price Manipulation A06)
    # User will do this manually in the attack scenario, but we can pre-create one
    
    # 4. Create Chat Room (Victim selling to Attacker) - A01: IDOR Target
    chat_room, _ = ChatRoom.objects.get_or_create(
        product=product,
        buyer=attacker,
        seller=victim
    )
    print(f"Created chat room ID: {chat_room.id}")

    # 5. Create Board Posts (for A05 SQLi)
    Post.objects.get_or_create(
        title='Secret Admin Notice',
        author=User.objects.get(username='admin'),
        defaults={
            'content': 'This contains sensitive admin information. DO NOT LEAK.'
        }
    )
    
    Post.objects.get_or_create(
        title='Hello World',
        author=victim,
        defaults={
            'content': 'Just a normal post.'
        }
    )
    print("Created board posts for SQLi testing")


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
        ('board', '0001_initial'),
        ('chat', '0001_initial'),
        ('market', '0001_initial'), 
    ]

    operations = [
        migrations.RunPython(create_test_data),
    ]
