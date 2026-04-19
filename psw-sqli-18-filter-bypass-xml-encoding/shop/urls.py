from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("product/stock", views.stock_check, name="stock_check"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("my-account", views.my_account, name="my_account"),
]
