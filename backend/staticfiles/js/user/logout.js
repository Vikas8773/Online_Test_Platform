var token = $("input[name='csrfmiddlewaretoken']").val();

var url = "/api/accounts/logout";
var type = "POST";
$.ajax({
       async: true,
       type: type,
       url: url,
       data: {
            'csrfmiddlewaretoken': token
       },
       success: function(data)
       {
            if(data['status']){
                window.location.href = '/accounts/login';
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
