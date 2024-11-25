from datetime import datetime, timedelta

from django.contrib.auth.views import PasswordResetView
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from .forms import RegisterForm, LoginForm
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.shortcuts import redirect, render
from datetime import datetime, timedelta
from .forms import *
import random


def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)  # Не сохраняем в БД сразу
            user.is_active = False  # Делаем пользователя неактивным до подтверждения

            # Отправляем код подтверждения
            send_verification_email(request, user)  # Передаем объект request

            # Сохраняем данные пользователя во временных переменных сессии
            request.session['username'] = user.username
            request.session['email'] = user.email
            request.session['password'] = user.password  # Важно: пароли следует хешировать перед сохранением в сессии

            return redirect('verify_email')  # Перенаправляем на страницу с проверкой кода
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})


def send_verification_email(request, user):
    verification_code = str(random.randint(100000, 999999))  # Генерируем 6-значный код
    subject = "Подтверждение электронной почты"
    message = f"Здравствуйте, {user.username}. Ваш код подтверждения: {verification_code}"

    # Сохраняем код подтверждения в сессии для проверки
    request.session['verification_code'] = verification_code
    request.session['user_id'] = user.id  # Сохраняем ID пользователя для дальнейшей проверки

    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


def verify_email(request):
    form = VerificationCodeForm()

    if request.method == 'POST':
        form = VerificationCodeForm(request.POST)

        if form.is_valid():
            code = form.cleaned_data.get('code')

            if code == request.session.get('verification_code'):
                # Создайте нового пользователя и сохраните его в БД
                username = request.session.get('username')
                email = request.session.get('email')
                password = request.session.get('password')

                # Создаем пользователя и сохраняем в БД
                user = User.objects.create_user(username=username, email=email, password=password)
                user.is_active = True  # Активируем пользователя
                user.save()

                # Удаляем данные из сессии после успешной регистрации
                del request.session['username']
                del request.session['email']
                del request.session['password']

                login(request, user)  # Автоматически входим в систему
                return redirect('home')
            else:
                form.add_error('code', 'Неверный код подтверждения.')

    return render(request, 'verify_email.html', {'form': form})













def user_login(request):
    if 'username' in request.COOKIES:
        return redirect('home')
    else:
        if request.method == 'POST':
            form = LoginForm(data=request.POST)
            if form.is_valid():
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')

                # Проверяем на существование пользователя
                User = get_user_model()
                if User.objects.filter(username=username).exists():
                    user = authenticate(request, username=username, password=password)
                    if user is not None:
                        login(request, user)
                        response = redirect('home')
                        expires = datetime.utcnow() + timedelta(seconds=10)
                        response.set_cookie('username', username, expires=expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT"))
                        return response
                    else:
                        print('Неверный пароль')
                        form.add_error(None, 'Неверный пароль.')
                else:
                    print('Неверный пользователь')
                    form.add_error(None, 'Пользователь не существует.')
        else:
            form = LoginForm()

        return render(request, 'login.html', {'form': form})








def password_reset_request(request):
    if request.method == "POST":
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            # Попробуем получить пользователя по email
            try:
                user = User.objects.get(email=email)

                # Генерация токена и uid
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)

                # Создаем ссылку для сброса пароля
                password_reset_link = f"http://127.0.0.1:8000/reset/{uid}/{token}/"

                subject = "Восстановление пароля"
                message = f"Здравствуйте, {user.username}. Чтобы сменить пароль, пройдите по следующей ссылке: {password_reset_link}"
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

                return redirect('password_reset_done')  # Успешный запрос
            except User.DoesNotExist:
                print(f"Проверяем email: {email}")
                # Информируем пользователя о том, что адрес электронной почты не найден
                form.add_error('email', 'Пользователь с таким адресом электронной почты не найден.')
        else:
            print(form.errors)
    else:
        form = PasswordResetRequestForm()

    return render(request, 'password_reset_form.html', {'form': form})




def home(request):
    return render(request, 'home.html')

def scan(request):
    return render(request, 'scan.html')
def anallog(request):
    return render(request, 'anallog.html')
def webpdf(request):
    return render(request, 'webpdf.html')
def monlog(request):
    return render(request, 'monlog.html')