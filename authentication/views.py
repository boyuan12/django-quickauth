from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect

# Create your views here.
def register(request):
    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]

        User.objects.create_user(email=email, username=email, password=password)

        return render(request, "authentication/registered.html")

    else:
        return render(request, "authentication/register.html")


def login_view(request):
    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]

        user = authenticate(username=email, password=password)

        if user is not None:
            login(request, user)
            return HttpResponseRedirect("/")
        else:
            return render(request, "authentication/invalid.html")

    else:
        return render(request, "authentication/login.html")


def logout_view(request):
    logout(request)
    return HttpResponseRedirect("/")
