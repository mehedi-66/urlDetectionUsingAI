from django.urls import path

from . import views

urlpatterns = [
    path('', views.Welcome, name='Welcome'),
    path('url', views.Url, name='Url'),
    path('testurl', views.TestUrl, name='TestUrl'),
    path('about', views.About, name='About')
]