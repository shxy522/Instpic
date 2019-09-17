from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)


class MyUserManager(BaseUserManager):
    def create_user(self, email, password=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser):
    email = models.CharField(
        verbose_name='email',
        max_length=255,
        unique=True,
        error_messages={"unique":"email already taken."}
    )

    username = models.CharField(
        verbose_name='username',
        max_length=255,
        unique=True,
        error_messages={"unique": "username already taken."}
    )
    img = models.ImageField(upload_to='img',default='')
    objects = MyUserManager()
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
    object = MyUserManager()


class IMG(models.Model):
    img = models.ImageField(upload_to='img')
    name = models.CharField(max_length=100, blank=True, default='')
    date = models.DateTimeField(auto_now_add=True)
    username= models.CharField(max_length=100 , default='')
    likes = models.CharField(max_length=255 , default='')
    likesnum = models.IntegerField(default=0)
    click = models.IntegerField(default=0)
    typename = models.CharField(max_length=100, default='')

    class Meta:
        ordering = ('-date',)

    def __str__(self):
        return self.title


class IMG1(models.Model):
    img = models.ImageField(upload_to='img')
    name = models.CharField(max_length=100, blank=True, default='')
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-date',)

