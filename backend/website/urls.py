from . import views
from django.urls import path, include

urlpatterns = [
    path('', views.User.home),
    path('error', views.Error.error),
    path('accounts/login', views.User.login),
    path('accounts/register', views.User.register),
    path('accounts/logout', views.User.logout),
    path('accounts/forgot_password', views.User.forgot_password),
    path('accounts/reset_password', views.User.reset_password),
    path('accounts/verify', views.User.verify_email),
    path('accounts/email_sent', views.User.email_sent),

    path('dashboard', views.Dashboard.dashboard),
    path('test/<id>', views.Dashboard.test),
    path('profile', views.Dashboard.profile),
    path('settings', views.Dashboard.settings),
    path('exam_list', views.Dashboard.exam_list),

    path('examine', views.Examine.examine),
    path('examine/uploaded_test_list', views.Examine.uploaded_test_list),
    path('examine/add_test', views.Examine.add_test),
    path('examine/add_test2', views.Examine.add_test),
    path('examine/test/<id>', views.Examine.test),
    path('examine/edit_test/<id>', views.Examine.edit_test),
    path('examine/result_list/<id>', views.Examine.result_list),

    path('examine/add_question/<id>', views.Examine.add_question),
    path('examine/question/<id>', views.Examine.question),
    path('examine/edit_question/<id>', views.Examine.edit_question),

    path('exam', views.Exam.exam),
    path('instruction', views.Exam.instruction),
    path('result/<id>', views.Exam.result),
]
