$("#register-form").submit(function(e) {
    if($("#password").val() !== $("#retype_password").val()){
        alert("Password not matched");
        return false;
    }

    $("#register-submit").attr('disabled','disabled');
    $("#register-loading").removeClass("d-none");

    e.preventDefault();
    var form = $(this);
    var url = form.attr('action');
    var type = form.attr('method');
    $.ajax({
           async: true,
           type: type,
           url: url,
           data: form.serialize(),
           success: function(data)
           {
                if(data['status']){

                    window.location.href = '/accounts/email_sent';
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = '/error?error=400 - BAD REQUEST&message=' + data['data']['message'];
                    }
                    else{
                        $("#register-submit").removeAttr('disabled');
                        $("#register-loading").addClass("d-none");
                        $("#register-msg").html(data['data']['message']);
                    }
                }
           },
            error: function (data) {
                console.log('An error occurred.');
                console.log(data);
            },
         });
    return false;
});

var visible_password = false;

$(document).on('click', "#visible-password", function(e){
    if(!visible_password){
        $('#password').get(0).type = 'text';
        $('#password-eye').removeClass('fa-eye').addClass('fa-eye-slash');
        visible_password = true
    }
    else{
        $('#password').get(0).type = 'password';
        $('#password-eye').removeClass('fa-eye-slash').addClass('fa-eye');
        visible_password = false
    }
})


