from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from .models import Verification
from helpers import send_mail
from django.contrib.sites.models import Site

# Create your views here.
def verification_link(user, email):
    Verification(user_id=user.id).save()

    try:
        v = Verification.objects.get(user_id=user.id)
    except Verification.MultipleObjectsReturned:
        v = Verification.objects.filter(user_id=user.id)[::-1][0]

    domain = Site.objects.get_current().domain
    if domain == "example.com":
        domain = "127.0.0.1:8000"

    send_mail(email, "Email Verify", f"Please click this <a href='http://{domain}/auth/verify/{v.code}'>link</a> to verify your account")


def register(request):

    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]

        User.objects.create_user(email=email, username=email, password=password)
        user = User.objects.get(username=email)

        verification_link(user, email)

        return render(request, "authentication/registered.html")

    else:
        return render(request, "authentication/register.html")


def login_view(request):
    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]

        user = authenticate(username=email, password=password)

        if user is not None:
            try:
                Verification.objects.get(user_id=user.id)
                return render(request, "authentication/invalid.html", {
                    "message": "Please complete email verification. Click to <a href='/auth/verify/new/'>re-request a email verification</a>"
                })
            except Verification.DoesNotExist:
                login(request, user)
                return HttpResponseRedirect("/")
        else:
            return render(request, "authentication/invalid.html", {
                "message": "Invalid Credentials"
            })

    else:
        return render(request, "authentication/login.html")


def logout_view(request):
    logout(request)
    return HttpResponseRedirect("/")


def verify(request, code):
    try:
        user_id = Verification.objects.get(code=code).user_id
        Verification.objects.get(code=code).delete()
        Verification.objects.filter(user_id=user_id).delete()
        return HttpResponseRedirect("/auth/login/")
    except Verification.DoesNotExist:
        return render(request, "invalid.html", {
            "message": "Code is not valid or already used"
        })


def verify_new(request):
    if request.method == "POST":
        try:
            user = User.objects.get(email=request.POST["email"])
            verification_link(user, request.POST["email"])
        except User.DoesNotExist:
            pass

        return render(request, "authentication/success.html", {
            "message": "Sent to your mailbox!"
        })

    else:
        return render(request, "authentication/new-verify.html")

