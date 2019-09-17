"""my_app URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.urls import path
from django.conf.urls import url
from django.views.generic import TemplateView
import account_app.views as BlogAppViews
from my_app import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^$', BlogAppViews.Home.as_view(), name='home'),
    url(r'^login/$', BlogAppViews.Login.as_view(),
        name='blog_app_login'),
    url(r'^register/$', BlogAppViews.register_method, name='register'),
    url(r'^me/$', BlogAppViews.Me.as_view(),
        name='blog_app_me'),
    url(r'^logout/$', BlogAppViews.Logout.as_view(), name='logout'),
    url(r'^changeemail/$', BlogAppViews.EditUser.as_view(), name='changeemail'),
    url(r'^changePassword/$', BlogAppViews.EditPassword.as_view(), name='changePassword'),
    url(r'^uploadimg/$', BlogAppViews.uploadimg, name='uploadimg'),
    url(r'^showimg/$', BlogAppViews.showimg, name='showimg'),
    url(r'^myimg/$', BlogAppViews.myimg, name='myimg'),


]+static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)
