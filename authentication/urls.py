from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.register),
    path("login/", views.login_view),
    path("logout/", views.logout_view),
    path("verify/<uuid:code>/", views.verify),
    path("verify/new/", views.verify_new),
    path("forgot-password/", views.forgot_password_request),
    path("reset-password/<uuid:token>/", views.reset_password),
]