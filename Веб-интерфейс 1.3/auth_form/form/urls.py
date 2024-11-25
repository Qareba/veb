

from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth import views as auth_views
from django.urls import path
from form import views

class CustomPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'
    form_class = SetPasswordForm


urlpatterns = [
    path('', views.user_login, name='login'),
    path('login/', views.user_login, name='login'),
    path('register/', views.register, name='register'),
    path('verify-email/', views.verify_email, name='verify_email'),
    path('home/', views.home, name='home'),
    path('scan/', views.scan, name='scan'),
    path('analizelogs/', views.anallog, name='anallog'),
    path('webpdf/', views.webpdf, name='webpdf'),
    path('monlog/', views.monlog, name='monlog'),
    path('password_reset/', views.password_reset_request, name='password_reset'),

    path('reset/done/',
         auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'),
         name='password_reset_done'),

    path('reset/complete/',
         auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),
         name='password_reset_complete'),

    path('reset/<uidb64>/<token>/',
         CustomPasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'),
         name='password_reset_confirm'),
]