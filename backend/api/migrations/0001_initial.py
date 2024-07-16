# Generated by Django 3.2.7 on 2021-10-17 17:49

import api.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserInformation',
            fields=[
                ('id', models.UUIDField(default=api.models.get_uuid, primary_key=True, serialize=False, unique=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Test',
            fields=[
                ('id', models.UUIDField(default=api.models.get_uuid_test, primary_key=True, serialize=False, unique=True)),
                ('title', models.CharField(max_length=200)),
                ('subject', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, default=None, null=True)),
                ('total_questions', models.IntegerField(default=0)),
                ('marks_per_question', models.FloatField(default=1.0)),
                ('total_time', models.DurationField()),
                ('from_date', models.DateTimeField(blank=True, default=None, null=True)),
                ('till_date', models.DateTimeField(blank=True, default=None, null=True)),
                ('status', models.BooleanField(default=False)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('modified_on', models.DateTimeField(auto_now=True)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Question',
            fields=[
                ('id', models.UUIDField(default=api.models.get_uuid_question, primary_key=True, serialize=False, unique=True)),
                ('title', models.CharField(default=None, max_length=200)),
                ('question', models.TextField()),
                ('option_1', models.TextField()),
                ('option_2', models.TextField()),
                ('option_3', models.TextField()),
                ('option_4', models.TextField()),
                ('correct_answer', models.IntegerField()),
                ('answer_key_description', models.TextField(blank=True, default=None, null=True)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('modified_on', models.DateTimeField(auto_now=True)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('test', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.test')),
            ],
        ),
        migrations.CreateModel(
            name='AnswerSheet',
            fields=[
                ('id', models.UUIDField(default=api.models.get_uuid_answer_sheet, primary_key=True, serialize=False, unique=True)),
                ('remaining_time', models.DurationField()),
                ('remaining_warning', models.IntegerField(default=5)),
                ('start_time', models.DateTimeField(auto_now_add=True)),
                ('end_time', models.DateTimeField(blank=True, default=None, null=True)),
                ('last_question', models.IntegerField(default=1)),
                ('status', models.BooleanField(default=False)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('modified_on', models.DateTimeField(auto_now=True)),
                ('test', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.test')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Answer',
            fields=[
                ('id', models.UUIDField(default=api.models.get_uuid_answer, primary_key=True, serialize=False, unique=True)),
                ('question_number', models.IntegerField()),
                ('answer', models.IntegerField(blank=True, default=None, null=True)),
                ('bookmark', models.BooleanField(default=False)),
                ('attempted', models.BooleanField(default=False)),
                ('time', models.DateTimeField(auto_now=True)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('modified_on', models.DateTimeField(auto_now=True)),
                ('answer_sheet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.answersheet')),
                ('question', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.question')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]