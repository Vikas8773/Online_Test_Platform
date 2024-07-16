var username = GetURLParameter('username');
var data = GetURLParameter('data');
var token = $("input[name='csrfmiddlewaretoken']").val();

var url = "/api/accounts/reset_password";
var type = "GET";
$.ajax({
       async: true,
       type: type,
       url: url,
       data: {
            'username': username,
            'data': data,
            'csrfmiddlewaretoken': token
       },
       success: function(data)
       {
            if(data['status']){
                $("#id").val(data['data']['id']);
                $("#reset-form").submit();
            }
            else{
                if(data['code'] == 400){
                    window.location.href = "/error?error=400 - BAD REQUEST&message="+data['data']['message'];
                }
            }
       },
        error: function (data) {
            console.log('An error occurred.');
            console.log(data);
        },
     });

function GetURLParameter(sParam)
{
    var sPageURL = window.location.search.substring(1);
    var sURLVariables = sPageURL.split('&');
    for (var i = 0; i < sURLVariables.length; i++)
    {
        var sParameterName = sURLVariables[i].split('=');
        if (sParameterName[0] == sParam)
        {
            return decodeURIComponent(sParameterName[1]);
        }
    }
}
