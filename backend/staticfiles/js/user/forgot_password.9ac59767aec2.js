$("#forgot-form").submit(function(e) {
    $("#forgot-submit").attr('disabled','disabled');
    $("#forgot-loading").removeClass("d-none");

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
                    $("#forgot-submit").removeAttr('disabled');
                    $("#forgot-loading").addClass("d-none");
                    $("#forgot-msg").html(data['data']['message']);
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = '/error?error=400 - BAD REQUEST&message=' + data['data']['message'];
                    }
                    else{
                        $("#forgot-submit").removeAttr('disabled');
                        $("#forgot-loading").addClass("d-none");
                        $("#forgot-msg").html(data['data']['message']);
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