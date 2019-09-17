from django import forms
from django.contrib.auth.hashers import check_password

from django import forms
from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
import re
from django.core.exceptions import ValidationError
from account_app.models import MyUser


def username_validate(value):
    mobile_re = re.compile(r'^[a-z0-9\-_]{3,}$')
    if not mobile_re.match(value):
        raise ValidationError('username is not valid')

class LoginForm(forms.Form):

    email = forms.CharField(label='email')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

    class Meta:
        model = MyUser
        fields = ('email', 'password',)


class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    email = forms.CharField(label='email',)
    username = forms.CharField(label='username',validators=[username_validate,])
    password1 = forms.CharField(label='password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = MyUser
        fields = ('email', 'username','password1','password2')

    def clean_email(self):
        email = self.cleaned_data.get("email")
        regex = "^[a-z0-9_-]+@[a-z0-9_-]+(\.[a-z0-9_-]+){1,3}$"
        if re.match(regex, email) is None:
            raise forms.ValidationError("enter a valid email address.")
        return email

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("password mismatch.")
        if len(password1) < 6:
            raise forms.ValidationError("password too short.")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class UserEmailForm(forms.ModelForm):
    email = forms.CharField(label='Email')
    class Meta:
        model = MyUser
        fields = ('email',)


class PasswordChangeForm(forms.ModelForm):
    password_old = forms.CharField(label='Password_old', widget=forms.PasswordInput)
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)
    class Meta:
        model = MyUser
        fields = ('password_old','password1','password2')

class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = MyUser
        fields = ('email', 'password', 'is_active', 'is_admin')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]


admin.site.register(MyUser)
# ... and, since we're not using Django's built-in permissions,
# unregister the Group model from admin.
admin.site.unregister(Group)

