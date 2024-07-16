from django.contrib.auth.decorators import login_required
from django.contrib.messages.storage import session
from django.shortcuts import render, redirect


class User:
    def home(self):
        if self.method == 'GET':
            if self.user.is_authenticated:
                return redirect("/dashboard")
            return render(self, "user/home.html")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def  register(self):
        if self.method == 'GET':
            if self.user.is_authenticated:
                return redirect("/dashboard")
            return render(self, "user/register.html")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def login(self):
        if self.method == 'GET':
            if self.user.is_authenticated:
                return redirect("/dashboard")
            return render(self, "user/login.html")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def logout(self):
        if self.user.is_authenticated:
            return render(self, "user/logout.html")
        else:
            return redirect("/accounts/login")

    def forgot_password(self):
        if self.method == 'GET':
            if not self.user.is_authenticated:
                return render(self, "user/forgot_password.html")
            else:
                return redirect('/')
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def reset_password(self):
        if self.method == 'GET':
            return render(self, "user/reset_password_get.html")
        elif self.method == 'POST':
            id = self.POST.get('id')
            return render(self, "user/reset_password.html", {
                'id': id
            })
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def verify_email(self):
        if self.method == 'GET':
            return render(self, "user/verify.html")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def email_sent(self):
        if self.method == 'GET':
            return render(self, "user/email_sent.html")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")


class Error:
    @staticmethod
    def error(request):
        if request.method == "GET":
            error = request.GET.get('error')
            message = request.GET.get('message')
            if error is None or message is None:
                return render(request, "error/index.html", {
                    'error': "404 - Not Found",
                    'message': "Error To Found"
                })
            else:
                return render(request, "error/index.html", {
                    'error': error,
                    'message': message
                })
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")


class Dashboard:
    def dashboard(self):
        if self.user.is_authenticated:
            return render(self, "dashboard/dashboard.html")
        else:
            return redirect("/")

    def profile(self):
        if self.user.is_authenticated:
            return render(self, "dashboard/profile.html")
        else:
            return redirect("/")

    def settings(self):
        if self.user.is_authenticated:
            return render(self, "dashboard/settings.html")
        else:
            return redirect("/")

    def exam_list(self):
        if self.user.is_authenticated:
            return render(self, "dashboard/exam_list.html")
        else:
            return redirect("/")

    def test(self, id):
        if self.user.is_authenticated:
            return render(self, "dashboard/test.html", {
                'id': id
            })
        else:
            return redirect("/")


class Examine:
    def examine(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/examine.html")
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def uploaded_test_list(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/uploaded_test_list.html")
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def add_test(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/add_test.html")
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def test(self, id):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/test.html", {
                        'id': id
                    })
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def edit_test(self, id):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/edit_test.html", {
                        'id': id
                    })
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def add_question(self, id):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/add_question.html", {
                        'id': id
                    })
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def question(self, id):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/question.html", {
                        'id': id
                    })
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def edit_question(self, id):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/edit_question.html", {
                        'id': id
                    })
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def result_list(self, id):
        if self.method == "GET":
            if self.user.is_authenticated:
                if self.user.is_staff:
                    return render(self, "examine/result_list.html", {
                        'id': id
                    })
                else:
                    return redirect("/error?error=403 - FORBIDDEN&message=Access Denied")
            else:
                return redirect("/")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")



class Exam:
    def exam(self):
        if self.method == "GET":
            if self.user.is_authenticated:
                id = self.session['exam'].get('answersheet')
                return render(self, "exam/exam.html", {
                    'id': id,
                })
            else:
                return redirect("/error?error=400 - BAD REQUEST&message=Not Permitted this Process")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def instruction(self):
        if self.method == "POST":
            if self.user.is_authenticated:
                id = self.POST.get('id')
                return render(self, "exam/instruction_exam.html", {
                    'id': id,
                })
            else:
                return redirect("/error?error=400 - BAD REQUEST&message=Not Permitted this Process")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")

    def result(self, id):
        if self.method == "GET":
            if self.user.is_authenticated:
                return render(self, "exam/result.html", {
                    'id': id
                })
            else:
                return redirect("/error?error=400 - BAD REQUEST&message=Not Permitted this Process")
        else:
            return redirect("/error?error=400 - BAD REQUEST&message=Wrong Request Method Used")
