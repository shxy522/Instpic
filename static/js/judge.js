function myregister(){
    var uPass = document.getElementById("id_password1").value;
    var uRePass = document.getElementById("id_password2").value;
    var umail = document.getElementById("id_email").value;
    var uname = document.getElementById("id_username").value;

    document.getElementById("errormsg").style.display="none";

    if(umail.length == 0){
    document.getElementById("errormsg").innerHTML = "email is null.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    var emailReg = /^[a-z0-9_-]+@[a-z0-9_-]+(\.[a-z0-9_-]+){1,3}$/;
    if ( ! emailReg.test(umail) ) {
    document.getElementById("errormsg").innerHTML = "enter a valid email address.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    if(uname.length == 0){
    document.getElementById("errormsg").innerHTML = "username is null.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    var nameVe =/^[a-z0-9\-_]{3,}$/;
    var nameReg = /^([a-z]|[0-9]|-|_)+$/;
    if ( ! nameReg.test(uname) ) {
    document.getElementById("errormsg").innerHTML = "username has illegal characters.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    if(uname.length < 4){
    document.getElementById("errormsg").innerHTML = "username is too short(<4).";
    document.getElementById("errormsg").style.display="block";
    return false;
    }
    if(uPass.length == 0){
    document.getElementById("errormsg").innerHTML = "password is null.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    if(uPass.length < 6){
    document.getElementById("errormsg").innerHTML = "password too short.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }
     if(uRePass.length == 0){
    document.getElementById("errormsg").innerHTML = "password confirm is null.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }


    if(uPass != uRePass){
    document.getElementById("errormsg").innerHTML = "password mismatch.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    return true;
}

function mychange(){
    var uPass = document.getElementById("id_password1").value;
    var uRePass = document.getElementById("id_password2").value;

    document.getElementById("errormsg").style.display="none";

    if(uPass.length < 6){
    document.getElementById("errormsg").innerHTML = "password too short.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }
    if(uPass != uRePass){
    document.getElementById("errormsg").innerHTML = "password mismatch.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    return true;
}

function mylogin(){

    var uPass = document.getElementById("id_password").value;

    document.getElementById("errormsg").style.display="none";


    if(uPass.length == 0){
    document.getElementById("errormsg").innerHTML = "password is null.";
    document.getElementById("errormsg").style.display="block";
    return false;
    }

    return true;

}