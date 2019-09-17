import math
import os

import re
from PIL import Image, ImageFilter
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from django.contrib import auth
from account_app.models import MyUser, IMG, IMG1
from account_app.forms import *
from django.utils.decorators import method_decorator
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.core.validators import validate_email
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
import PIL
import time




class Home(TemplateView):
    template_name = "mainpage.html"
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return render(request, 'mainpage.html')
            #return HttpResponseRedirect('/')
        else:
            return render(request, self.template_name)
            #return HttpResponseRedirect('/login')



class Login(FormView):
    model = MyUser
    template_name = "index.html"
    form_class = LoginForm

    def get(self, request, *args, **kwargs):
        auth.logout(request)
        return render(request, self.template_name)
    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)

        if form.is_valid():
            email = request.POST.get('email')
            password = request.POST.get('password')

            user_list = MyUser.object.all()
            for line in user_list:
                if email == line.email:
                    username = line.username
                if email == line.username:
                    username = line.username
            user = auth.authenticate(request, username=email, password=password)
            # if user is None:
            #      user = auth.authenticate(request, username=username, password=password)

            if user is None:

                email_judge = '@'
                result = email_judge in email

                username_valid =False
                email_valid = False
                if result:
                    for line in user_list:
                        if email == line.email:
                            email_valid = True
                        else:
                            continue
                    if email_valid is False:
                        return render(request, self.template_name, {'form': form, 'errormsg': 'email not found.'})
                else:
                    for line in user_list:
                        if email == line.username:
                            username_valid = True
                        else:
                            continue
                    if username_valid is False:
                        return render(request, self.template_name,
                                      {'form': form, 'errormsg': 'username not found.'})
            if user is None:
                return render(request, self.template_name, {'form': form, 'errormsg': 'password is invalid.'})
            elif user is not None:
                auth.login(request, user)
                return HttpResponseRedirect('/me')

        return render(request, self.template_name, {'form': form})


class Register(FormView):
    model = MyUser
    template_name = "regist.html"
    form_class = UserCreationForm

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        email = request.POST.get('email')
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        user = auth.authenticate(request, username=username, password1=password1)

        user_list = MyUser.object.all()
        email_valid = False
        username_valid = False
        if form.is_valid():
            form.save(commit=True)
            return HttpResponseRedirect('/login')
        else:
            for line in user_list:
                if email != line.email:
                    continue
                else:
                    email_valid = True
            for line in user_list:
                if username != line.username:
                    continue
                else:
                    username_valid = True

            if email_valid is True:
                return render(request, self.template_name, {'form': form, 'errormsg': 'email already taken.'})
            if username_valid is True:
                return render(request, self.template_name, {'form': form, 'errormsg': 'username already taken.'})
            if password1 and password2 and password1 != password2:
                return render(request, self.template_name, {'form': form, 'errormsg': 'password mismatch.'})
            if len(password1) < 6:
                return render(request, self.template_name, {'form': form, 'errormsg': 'password too short.'})

            return HttpResponseRedirect('/login')
class Me(TemplateView):
    model = MyUser
    #template_name = "me.html"
    template_name = "modification.html"

    def post(self, request, *args, **kwargs):
        # auth.logout(request)
        return HttpResponseRedirect('/logout')

    @method_decorator(login_required())
    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {'username':request.user.username,'email': request.user.email, 'created': request.user.created_at})


def register_method(request):
    form = UserCreationForm(request.POST or None)
    template_name = "regist.html"
    context = {
        "form": form
    }
    email = request.POST.get('email')
    username = request.POST.get('username')
    password1 = request.POST.get('password1')
    password2 = request.POST.get('password2')
    user = auth.authenticate(request, username=username, password1=password1)

    user_list = MyUser.object.all()
    email_valid = False
    username_valid = False
    if form.is_valid():
        form.save()
        return redirect("/login")
    else:
        for line in user_list:
            if email != line.email:
                continue
            else:
                email_valid = True
        for line in user_list:
            if username != line.username:
                continue
            else:
                username_valid = True

        if email_valid is True:
            return render(request,  "regist.html", {'form': form, 'errormsg': 'email already taken.'})
        if username_valid is True:
            return render(request, "regist.html", {'form': form, 'errormsg': 'username already taken.'})
        if password1 and password2 and password1 != password2:
            return render(request, "regist.html", {'form': form, 'errormsg': 'password mismatch.'})
        error = form.errors
        return render(request, "regist.html", {'form': form, 'error': error})



class Logout(TemplateView):
    template_name = "logout.html"

    @method_decorator(login_required())
    def get(self, request, *args, **kwargs):
        auth.logout(request)
        return render(request, self.template_name)


class EditUser(TemplateView):
    template_name = "changeemail.html"
    model = MyUser
    form_class = UserEmailForm

    @method_decorator(login_required())
    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {'email': request.user.email})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            newemail = request.POST.get('email')
            item = request.user
            geteml = item.email

            regex = "^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$"
            if re.match(regex, newemail) is None:
                return render(request, self.template_name, {'email': request.user.email,'errormsg': 'Invalid email!'})

            if geteml != newemail:
                item.email = newemail
                item.save()
                return render(request, self.template_name, {'email': request.user.email})
            else:
                return render(request, self.template_name, {'errormsg': 'Email cannot be the same'})
        else:
            return render(request, self.template_name, {'email': request.user.email,'errormsg': 'email already taken.'})


class EditPassword(TemplateView):
    model = MyUser
    template_name = "changePassword.html"
    form_class = PasswordChangeForm

    @method_decorator(login_required())
    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            email = request.user.email
            old_password = form.cleaned_data['password_old']
            new_password1 = form.cleaned_data['password1']
            new_password2 = form.cleaned_data['password2']

            passwd = auth.authenticate(request, username=email, password=old_password)

            #passwd = MyUser.objects.filter(email=email, password=old_password)
            if passwd:
                # MyUser.objects.filter(email=email, password=old_password).update(password=new_password)  ##如果用户名、原密码匹配则更新密码

                if new_password1 and new_password2 and new_password1 != new_password2:
                    return render(request, self.template_name, {'errormsg': 'password mismatch.'})
                if len(new_password1) < 6:
                    return render(request, self.template_name, {'errormsg': 'password too short.'})
                if old_password == new_password1:
                    return render(request, self.template_name)

                item = request.user
                item.set_password(new_password1)
                item.save()
                auth.login(request, item)
                return HttpResponseRedirect('/me')
            else:
                info = 'invalid password.'

            return render(request, self.template_name, {'errormsg': info})
        else:
            return render(request, self.template_name)


class CustomBackend(ModelBackend):
    """邮箱也能登录"""
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user=MyUser.objects.get(Q(username=username)|Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None


@csrf_exempt
def uploadimg(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            select = request.POST.get('select')
            img = request.FILES.get('img')
            username = request.user.username

            timestamp = str(time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())))

            img.name = img.name[:-4] + timestamp +img.name[-4:]
            name = img.name

            new_img = IMG1(
                img=img,

            )
            new_img.save()


            path = 'media//img//' + img.name
            typename = 'original'

            if type(path) == str and path.endswith(('.png', '.gif', '.bmp', '.jpg')):
                path_new = 'media//img//' + '1' + img.name
                with Image.open(path) as im:
                    w, h = im.size

                    w_s = 1000
                    h_s = 1000
                    if w> 1000 or h > 1000:
                        if w > h :
                            w_s = 1000
                            h_s = h * w_s / w
                            h_s = math.floor(h_s)
                            w = w_s
                            h = h_s
                            im.resize((w, h), Image.ANTIALIAS)
                        else:
                            h_s = 1000
                            w_s = w * h_s / h
                            w_s = math.floor(w_s)
                            w = w_s
                            h = h_s
                            im = im.resize((w, h), Image.ANTIALIAS)

                    if select == '1':
                        typename = 'original'
                        im.convert('RGB').resize((w, h), Image.ANTIALIAS).save(
                            path_new[:-3] + 'jpg')
                    if select == '2':
                        typename = 'grey'
                        im.convert('L').resize((w, h), Image.ANTIALIAS).save(
                            path_new[:-3] + 'jpg')
                    if select == '3':
                        typename = 'enhance'
                        im.convert('RGB').filter(ImageFilter.EDGE_ENHANCE).resize((w, h), Image.ANTIALIAS).save(
                            path_new[:-3] + 'jpg')
                    if select == '4':
                        typename = 'emomboss'
                        im.convert('RGB').filter(ImageFilter.EMBOSS).resize((w, h), Image.ANTIALIAS).save(
                            path_new[:-3] + 'jpg')
                    if select == '5':
                        typename = 'contour'
                        im.convert('RGB').filter(ImageFilter.CONTOUR).resize((w, h), Image.ANTIALIAS).save(
                            path_new[:-3] + 'jpg')
                    if select == '6':
                        typename = 'gaussianblur'
                        im.convert('RGB').filter(ImageFilter.GaussianBlur(radius=10)).resize((w, h), Image.ANTIALIAS).save(
                            path_new[:-3] + 'jpg')

            mimg = 'img//' + '1'+ img.name[:-3] + 'jpg'
            modify_img = IMG(
                img=mimg,
                username=username,
                name=name,
                typename=typename,
            )
            modify_img.save()

            return render(request, 'upload_try.html',{'success':'upload success!'})
        else:
            return render(request,'upload_try.html')
    else:
        return redirect('/login')


@csrf_exempt
def showimg(request):
    if request.user.is_authenticated:
        if request.method == 'GET':
            # imgs = IMG.objects.filter(username= request.user.username)
            imgs = IMG.objects.all()
            for i in imgs:
                judge = i.likes.split(',')

                judge_exist = False

                for j in judge:
                    if (j == request.user.username):
                        judge_exist = True
                if judge_exist is True:
                    i.click = 1

            imgcolumns=[]
            img4=[]
            count=0
            column=0
            for i in imgs:
                count+=1
                img4.append(i)
                if(count%4==0):
                    imgcolumns.append(img4)
                    img4=[]
                    column+=1
            imgcolumns.append(img4)


            content = {
                'imgcolumns':imgcolumns,
            }
            return render(request, 'square.html', content)
        if request.method == 'POST':
            # imgs = IMG.objects.filter(username=request.user.username)
            # imgs = IMG.objects.all().order_by('-likesnum')
            name = request.POST.get('name')
            original = request.POST.get('original')
            grey = request.POST.get('grey')
            enhance= request.POST.get('enhance')
            emoboss= request.POST.get('emoboss')
            contour= request.POST.get('contour')
            gaussianblur= request.POST.get('gaussianblur')

            if original is not None or grey is not None or enhance is not None or emoboss is not None or contour is not None or gaussianblur is not None:
                if original is not None:
                    imgs = IMG.objects.filter(typename= original)
                if grey is not None:
                    imgs = IMG.objects.filter(typename= grey)
                if enhance is not None:
                    imgs = IMG.objects.filter(typename= enhance)
                if emoboss is not None:
                    imgs = IMG.objects.filter(typename= emoboss)
                if contour is not None:
                    imgs = IMG.objects.filter(typename= contour)
                if gaussianblur is not None:
                    imgs = IMG.objects.filter(typename= gaussianblur)
                imgcolumns = []
                img4 = []
                count = 0
                column = 0
                for i in imgs:
                    count += 1
                    img4.append(i)
                    if (count % 4 == 0):
                        imgcolumns.append(img4)
                        img4 = []
                        column += 1
                imgcolumns.append(img4)

                content = {
                    'imgcolumns': imgcolumns,
                }

                return render(request, 'square.html', content)
            if IMG.objects.get(name=name) is not None:
                imgs = IMG.objects.all()
                like = request.POST.get('likes')
                username = request.user.username
                timg =IMG.objects.get(name=name)

                judge = timg.likes.split(',')

                judge_exist = False
                new_likes = ''
                for i in judge:

                    if(i == username):

                        new_likes =new_likes[0:len(new_likes)-1]
                        judge_exist = True
                    else:

                        new_likes = new_likes + i + ','

                if judge_exist is False:
                    timg.likesnum = timg.likesnum + 1
                    timg.likes = timg.likes + username + ','
                else:
                    timg.likesnum = timg.likesnum - 1

                    timg.likes =new_likes
                    if len(timg.likes) <3:
                        timg.likes = ''

                IMG.objects.filter(name=name).update(likes=timg.likes,likesnum=timg.likesnum)

                imgs = IMG.objects.all()
                for i in imgs:
                    judge = i.likes.split(',')

                    judge_exist = False

                    for j in judge:
                        if (j == request.user.username):
                            judge_exist = True
                    if judge_exist is True:
                        i.click = 1

                imgcolumns = []
                img4 = []
                count = 0
                column = 0
                for i in imgs:
                    count += 1
                    img4.append(i)
                    if (count % 4 == 0):
                        imgcolumns.append(img4)
                        img4 = []
                        column += 1
                imgcolumns.append(img4)

                content = {
                    'imgcolumns': imgcolumns,
                }

                return render(request, 'square.html', content)
    else:
        return redirect('/login')

@csrf_exempt
def myimg(request):
    if request.user.is_authenticated:
        if request.method == 'GET':
            imgs = IMG.objects.filter(username= request.user.username)

            for i in imgs:
                judge = i.likes.split(',')

                judge_exist = False

                for j in judge:
                    if (j == request.user.username):
                        judge_exist = True
                if judge_exist is True:
                    i.click = 1

            imgcolumns=[]
            img4=[]
            count=0
            column=0
            for i in imgs:
                count+=1
                img4.append(i)
                if(count%4==0):
                    imgcolumns.append(img4)
                    img4=[]
                    column+=1
            imgcolumns.append(img4)

            content = {
                'imgcolumns':imgcolumns,
            }

            return render(request, 'myImage.html', content)
        if request.method == 'POST':
            if 'likes' in request.POST:

                like = request.POST.get('likes')
                name = request.POST.get('name')
                username = request.user.username
                timg =IMG.objects.get(name=name)

                judge = timg.likes.split(',')

                judge_exist = False
                new_likes = ''
                for i in judge:

                    if(i == username):

                        new_likes =new_likes[0:len(new_likes)-1]
                        judge_exist = True
                    else:

                        new_likes = new_likes + i + ','

                if judge_exist is False:
                    timg.likesnum = timg.likesnum + 1
                    timg.likes = timg.likes + username + ','
                else:
                    timg.likesnum = timg.likesnum - 1

                    timg.likes =new_likes
                    if len(timg.likes) <3:
                        timg.likes = ''

                IMG.objects.filter(name=name).update(likes=timg.likes,likesnum=timg.likesnum)


                imgs = IMG.objects.filter(username=request.user.username)

                imgcolumns = []
                img4 = []
                count = 0
                column = 0
                for i in imgs:
                    count += 1
                    img4.append(i)
                    if (count % 4 == 0):
                        imgcolumns.append(img4)
                        img4 = []
                        column += 1

                content = {
                    'imgcolumns': imgcolumns,
                }

                return redirect('/myimg')

            elif 'delete' in request.POST:
                name = request.POST.get('name')
                IMG.objects.filter(name=name).delete()
                imgs = IMG.objects.all()
                content = {
                    'imgs': imgs,
                }

                return redirect('/myimg')
    else:
        return redirect('/login')
