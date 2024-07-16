$("#login-form").submit(function(e) {
    $("#login-submit").attr('disabled','disabled');
    $("#login-loading").removeClass("d-none");

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
                    window.location.href = '/dashboard';
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = '/error?error=400 - BAD REQUEST&message=' + data['data']['message'];
                    }
                    else{
                        $("#login-submit").removeAttr('disabled');
                        $("#login-loading").addClass("d-none");
                        $("#login-msg").html(data['data']['message']);
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