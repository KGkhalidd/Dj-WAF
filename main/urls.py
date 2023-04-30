from django.urls import path
from . import views

app_name='main'

urlpatterns = [
    path('', views.Login,name='login-light'),
    
    path('logout/',views.logout_view,name='logout_view'),

    path('dashboard/', views.view_dashboard,name='dashboard'),  

    

    path('Change-password-light/', views.change_password,name='Change-password-light'),
    
    path('log-analysis-light/', views.log_analysis_light,name='log-analysis-light'),  
    path('ip-blocker-light/', views.ip_blocker_light,name='ip-blocker-light'),  
    path('vulnerability-filtering-light/', views.vulnerability_filtering_light,name='vulnerability-filtering-light'),  
    path('Custom-filter-light/', views.Custom_filter_light,name='Custom-filter-light'),  
    path('server-Configurations-light/', views.server_Configurations_light,name='server-Configurations-light'),  
    path('Reporting-light/', views.Reporting_light,name='Reporting-light'),  
    path('Users-and-Permissions-light/', views.Users_and_Permissions_light,name='Users-and-Permissions-light'),






]
