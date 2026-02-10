from django.db import migrations


DEFAULT_CATEGORIES = [
    ("전자기기", "electronics"),
    ("도서", "books"),
    ("음악", "music"),
    ("의류", "clothing"),
    ("가구/인테리어", "furniture"),
    ("생활/주방", "home-kitchen"),
    ("스포츠/레저", "sports"),
    ("게임", "games"),
    ("취미/굿즈", "hobby-goods"),
    ("뷰티/미용", "beauty"),
    ("유아/아동", "kids"),
    ("반려동물", "pets"),
    ("기타", "etc"),
]


def create_default_categories(apps, schema_editor):
    Category = apps.get_model("market", "Category")
    for name, slug in DEFAULT_CATEGORIES:
        Category.objects.get_or_create(slug=slug, defaults={"name": name})


def delete_default_categories(apps, schema_editor):
    Category = apps.get_model("market", "Category")
    slugs = [slug for _, slug in DEFAULT_CATEGORIES]
    Category.objects.filter(slug__in=slugs).delete()


class Migration(migrations.Migration):
    # 0001_initial 은 사용자가 컨테이너에서 makemigrations market 실행 시 생성됩니다.
    dependencies = [
        ("market", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_default_categories, delete_default_categories),
    ]

