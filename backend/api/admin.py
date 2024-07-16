from django.contrib import admin

from .models import UserInformation, Test, Question, AnswerSheet, Answer


@admin.register(UserInformation)
class UserInformationAdmin(admin.ModelAdmin):
    pass


@admin.register(Test)
class TestAdmin(admin.ModelAdmin):
    pass


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    pass


@admin.register(AnswerSheet)
class AnswerSheetAdmin(admin.ModelAdmin):
    pass


@admin.register(Answer)
class AnswerAdmin(admin.ModelAdmin):
    pass
