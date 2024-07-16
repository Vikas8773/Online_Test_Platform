$("#reset-form").submit(function(e) {
    if($("#password").val() !== $("#retype_password").val()){
        alert("Password not matched");
        return false;
    }

    $("#reset-submit").attr('disabled','disabled');
    $("#reset-loading").removeClass("d-none");

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
                    window.location.href = '/accounts/login';
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = '/error?error=400 - BAD REQUEST&message=' + data['data']['message'];
                    }
                    else{
                        $("#reset-submit").removeAttr('disabled');
                        $("#reset-loading").addClass("d-none");
                        $("#reset-msg").html(data['data']['message']);
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