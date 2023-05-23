from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, update_session_auth_hash, logout
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.contrib import messages
from django.urls import reverse
from django.views import View
from django.core.cache import cache
import re
from .models import Pattern, Blockedclient
from .forms import Patternform, Blockedclientform
from django.http import HttpRequest
import json

# def extract_requests(request):
#     file_path = "waf.txt"  # Replace with the actual file path

#     # Initialize variables to store extracted data
#     ids = []
#     paths = []
#     endpoints = []
#     methods = []
#     body_data = []

#     # Read the file containing the requests
#     with open(file_path, "r") as file:
#         requests_data = file.readlines()

#     # Process each request
#     for i, request_str in enumerate(requests_data, start=1):
#         # Parse the request string as JSON
#         request = json.loads(request_str)

#         # Extract the desired information
#         method = request.get("method")
#         path = request.get("path")
#         body_params = request.get("body_params")

#         # Generate the endpoint by combining method and path
#         endpoint = f"{method} {path}"

#         # Store the extracted data
#         ids.append(i)
#         methods.append(method)
#         paths.append(path)
#         endpoints.append(endpoint)
#         body_data.append(body_params)

#     context = {
#         'ids': ids,
#         'methods': methods,
#         'paths': paths,
#         'endpoints': endpoints,
#         'body_data': body_data,
#     }

#     return render(request, 'Log-analysis-light.html', context)



def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
        print("ip address of user is :", ip)
    return ip


def blockpattern(request):
    client_ip = request.META.get('REMOTE_ADDR')
    is_blocked = Blockedclient.objects.filter(client_ip=client_ip).exists()
    if is_blocked:
        return HttpResponse("Something went wrong.", status=403)
    else:

        patterns = Pattern.objects.filter(
            is_enabled=True).values_list("name", flat=True)
        pattern = "|".join(patterns)
        is_violating = bool(re.match(pattern, data))
        if is_violating:
            return HttpResponse("Something went wrong.", status=403)

        else:
            Blockedclient.objects.create(client_ip=client_ip)


@login_required(login_url='main:login-light')
def view_dashboard(request):
    client_ip = get_client_ip(request)
    print(client_ip)
    if Blockedclient.objects.filter(client_ip=client_ip).exists():
        return HttpResponse("Something went Wrong.")
    return render(request, 'main/dashboard.html', {'title': "dashboard"})


def Login(request):
    x = get_client_ip(request)
    print(x)
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('main:dashboard')

        else:
            return HttpResponse("Username or passward is not correct ")
    return render(request, 'main/login-light.html')


@login_required(login_url='main:login-light')
def change_password(request):
    print(request.method)
    if request.method == 'POST':
        old_password = request.POST.get("q_old_Password")
        new_password = request.POST.get("q_new_Password")
        confirmed_new_password = request.POST.get("q_confirm_new_Password")
        print(old_password)
        if old_password and new_password and confirmed_new_password:
            if request.user.is_authenticated:
                user = request.user
                if not user.check_password(old_password):
                    messages.warning(
                        request, "your old password is not correct!")
                    print("your old password is not correct!")
                else:
                    if new_password != confirmed_new_password:
                        messages.warning(
                            request, "your new password not match the confirm password !")

                    elif len(new_password) < 8 or new_password.lower() == new_password or \
                            new_password.upper() == new_password or new_password.isalnum() or \
                            not any(i.isdigit() for i in new_password):

                        messages.warning(request, "your password is too weak!")

                    else:

                        user.set_password(new_password)
                        user.save()
                        update_session_auth_hash(request, user)

                        messages.success(
                            request, "your password has been changed successfuly.!")
                        return redirect('main:dashboard')

        else:
            messages.warning(request, " sorry , all fields are required !")

    context = {

    }
    return render(request, "main/Change-password-light.html", context)


@login_required(login_url='main:login-light')
def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse('main:login-light'))

import json

def extract_requests(file_path):
    with open(file_path, "r") as file:
        requests_data = file.readlines()

    ids = []
    dates = []
    client_ips = []
    methods = []
    paths = []
    bodies = []
    endpoints = []
    vulnerabilities = []

    for i, request_str in enumerate(requests_data, start=1):
        try:
            request = json.loads(request_str)

            # Check if the line contains the string "An error occurred"
            if "An error occurred" in request_str:
                continue  # Skip the line if it contains the error message

            date = request.get("Date")
            client_ip = request.get("client_ip")
            method = request.get("method")
            path = request.get("path")
            body = request.get("body")
            endpoint = request.get("endpoint")
            vulnerable = request.get("vulnerable")

            # Store the extracted data
            ids.append(i)
            dates.append(date)
            client_ips.append(client_ip)
            methods.append(method)
            paths.append(path)
            bodies.append(body)
            endpoints.append(endpoint)
            vulnerabilities.append(vulnerable)
        except json.JSONDecodeError:
            # Handle JSON decoding errors
            continue  # Skip the line if it's not valid JSON

    # Reverse the order of the extracted data
    ids.reverse()
    dates.reverse()
    client_ips.reverse()
    methods.reverse()
    paths.reverse()
    bodies.reverse()
    endpoints.reverse()
    vulnerabilities.reverse()

    # Return the extracted data
    return ids, dates, client_ips, methods, paths, bodies, endpoints, vulnerabilities


@login_required(login_url='main:login-light')
def log_analysis_light(request):
    file_path = "F:\projects\djWAF\src\mywaf.txt"  # Replace with the actual file path
    ids, dates, client_ips, methods, paths, bodies, endpoints, vulnerabilities = extract_requests(file_path)

    data = []
    for i, _ in enumerate(ids, start=1):
        item = {
            'id': i,
            'date': dates[i-1],
            'client_ip': client_ips[i-1],
            'method': methods[i-1],
            'path': paths[i-1],
            'body': bodies[i-1],
            'endpoint': endpoints[i-1],
            'vulnerable': vulnerabilities[i-1]
        }
        data.append(item)

    context = {
        'title': "log-analysis-light",
        'blockedclients': Blockedclient.objects.all(),
        'data': data,
    }

    return render(request, 'main/log-analysis-light.html', context)


    


@login_required(login_url='main:login-light')
def ip_blocker_light(request):
    if request.method == 'POST':

        form = Blockedclientform(request.POST)
        if form.is_valid():
            print('form is valid')
            form.save()
            return redirect(reverse('main:ip-blocker-light'))
        else:
            print('in else')
            form = Blockedclientform()
            return render(request, 'main/ip-blocker-light.html', {'title': "ip-blocker-light"})

    else:

        return render(request, 'main/ip-blocker-light.html', {'title': "ip-blocker-light", "blockedclients": Blockedclient.objects.all()})


@login_required(login_url='main:login-light')
def vulnerability_filtering_light(request):
    return render(request, 'main/vulnerability-filtering-light.html', {'title': "vulnerability-filtering-light"})


@login_required(login_url='main:login-light')
def Custom_filter_light(request):

    if request.method == 'POST':

        form = Patternform(request.POST)
        if form.is_valid():
            print('form is valid')
            form.save()
            return redirect(reverse('main:Custom-filter-light'))

        else:
            print('in else')
            form = Patternform()
            return render(request, 'main/Custom-filter-light.html', {'title': "Custom-filter-light"})

    else:
        return render(request, 'main/Custom-filter-light.html', {'title': "Custom-filter-light", "patterns": Pattern.objects.all()})


@login_required(login_url='main:login-light')
def server_Configurations_light(request):
    return render(request, 'main/server-Configurations-light.html', {'title': "server-Configurations-light"})


@login_required(login_url='main:login-light')
def Reporting_light(request):
    return render(request, 'main/Reporting-light.html', {'title': "Reporting-light "})


@login_required(login_url='main:login-light')
def Users_and_Permissions_light(request):
    return render(request, 'main/Users-and-Permissions-light.html', {'title': "Users-and-Permissions-light"})
