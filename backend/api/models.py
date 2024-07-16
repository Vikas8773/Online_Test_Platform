import random
import uuid

from django.contrib.auth.models import User
from django.db import models


def get_uuid():
    while True:
        id = uuid.uuid4()
        if UserInformation.objects.filter(id=id).count() == 0:
            return id


class UserInformation(models.Model):
    id = models.UUIDField(default=get_uuid, primary_key=True, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.user.username)


def get_uuid_test():
    while True:
        id = uuid.uuid4()
        if Test.objects.filter(id=id).count() == 0:
            return id


class Test(models.Model):
    id = models.UUIDField(default=get_uuid_test, primary_key=True, unique=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    subject = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True, default=None)
    total_questions = models.IntegerField(default=0)
    marks_per_question = models.FloatField(default=1.0)
    total_time = models.DurationField()
    from_date = models.DateTimeField(default=None, blank=True, null=True)
    till_date = models.DateTimeField(default=None, blank=True, null=True)
    status = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.title)


def get_uuid_question():
    while True:
        id = uuid.uuid4()
        if Question.objects.filter(id=id).count() == 0:
            return id


class Question(models.Model):
    id = models.UUIDField(default=get_uuid_question, primary_key=True, unique=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    title = models.CharField(max_length=200, default=None)
    question = models.TextField()
    option_1 = models.TextField()
    option_2 = models.TextField()
    option_3 = models.TextField()
    option_4 = models.TextField()
    correct_answer = models.IntegerField()
    answer_key_description = models.TextField(default=None, blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.title)


def get_uuid_answer_sheet():
    while True:
        id = uuid.uuid4()
        if AnswerSheet.objects.filter(id=id).count() == 0:
            return id


class AnswerSheet(models.Model):
    id = models.UUIDField(default=get_uuid_answer_sheet, primary_key=True, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    remaining_time = models.DurationField()
    remaining_warning = models.IntegerField(default=5)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(default=None, null=True, blank=True)
    last_question = models.IntegerField(default=1)
    status = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if (Answer.objects.filter(user=self.user, answer_sheet=self).count() == 0) or (Answer.objects.filter(user=self.user, answer_sheet=self).count() < self.test.total_questions):
            questions_list = list(Question.objects.filter(test=self.test))
            random.shuffle(questions_list)
            question_count = 1
            for question in questions_list:
                if Answer.objects.filter(user=self.user, answer_sheet=self, question=question).count() == 0:
                    answer = Answer.objects.create(user=self.user, answer_sheet=self, question=question, question_number=question_count)
                    answer.save()
                else:
                    answer = Answer.objects.filter(user=self.user, answer_sheet=self, question=question).get()
                    answer.question_number = question_count
                    answer.save()
                question_count += 1


def get_uuid_answer():
    while True:
        id = uuid.uuid4()
        if Answer.objects.filter(id=id).count() == 0:
            return id


class Answer(models.Model):
    id = models.UUIDField(default=get_uuid_answer, primary_key=True, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    answer_sheet = models.ForeignKey(AnswerSheet, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    question_number = models.IntegerField()
    answer = models.IntegerField(default=None, blank=True, null=True)
    bookmark = models.BooleanField(default=False)
    attempted = models.BooleanField(default=False)
    time = models.DateTimeField(auto_now=True)
    created_on = models.DateTimeField(auto_now_add=True)
    modified_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)


