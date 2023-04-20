import requests
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib import messages
from ipwhois import IPWhois
from ipware import get_client_ip
from user_agents import parse
from .models import UserConnection

def landing(request):
    # Get the user's IP address
    ip_address, is_routable = get_client_ip(request)

    # Get the user's geolocation data using ipapi
    url = f'https://ipapi.co/{ip_address}/json/'
    response = requests.get(url)
    data = response.json()

    # Get the user's network provider and ASN
    ip = IPWhois(ip_address)
    result = ip.lookup_rdap()

    # Get the user's device information
    user_agent = parse(request.META.get('HTTP_USER_AGENT', ''))
    device_info = f'{user_agent.device.family} {user_agent.device.brand} {user_agent.device.model}'
    
    # Save the user connection data to the database
    user_connection = UserConnection.objects.create(
        ip=ip_address,
        network=result.get('network').get('cidr'),
        version=result.get('network').get('version'),
        city=data.get('city'),
        region=data.get('region'),
        region_code=data.get('region_code'),
        country=data.get('country'),
        country_name=data.get('country_name'),
        country_code=data.get('country_code'),
        country_code_iso3=data.get('country_code_iso3'),
        country_capital=data.get('country_capital'),
        country_tld=data.get('country_tld'),
        continent_code=data.get('continent_code'),
        in_eu=data.get('in_eu'),
        postal=data.get('postal'),
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        timezone=data.get('timezone'),
        utc_offset=data.get('utc_offset'),
        country_calling_code=data.get('country_calling_code'),
        currency=data.get('currency'),
        currency_name=data.get('currency_name'),
        languages=data.get('languages'),
        country_area=data.get('country_area'),
        country_population=data.get('country_population'),
        asn=result.get('asn'),
        org=result.get('network').get('name'),
        device_info=device_info
    )
    user_connection.save()

    # Render the response
    return render(request, 'index.html', context={})


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('landing')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('login')