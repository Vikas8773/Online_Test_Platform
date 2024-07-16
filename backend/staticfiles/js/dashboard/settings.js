$("#settings-form").submit(function(e) {
    $("#settings-submit").attr('disabled','disabled');
    $("#settings-loading").removeClass("d-none");

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
                    window.location.reload();
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = '/error?error=400 - BAD REQUEST&message=' + data['data']['message'];
                    }
                    else{
                        $("#settings-submit").removeAttr('disabled');
                        $("#settings-loading").addClass("d-none");
                        $("#settings-msg").html(data['data']['message']);
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