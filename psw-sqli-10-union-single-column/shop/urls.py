from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("filter", views.filter_products, name="filter_products"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("my-account", views.my_account, name="my_account"),
]
