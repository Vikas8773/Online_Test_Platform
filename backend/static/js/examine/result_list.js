$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#test-id").val();
    var url = "/api/examine/result_list";
    var type = "POST";
    $.ajax({
           async: true,
           type: type,
           url: url,
           data: {
                'id': id,
                'csrfmiddlewaretoken': token
           },
           success: function(data)
           {
                if(data['status']){
                    var data = data['data'];
                    var testListLength = data['test_list'].length;

                    var table = '<tbody id="table-body">';

                    for (var i = 0; i < testListLength; i++) {
                        table = table + `
                           <tr>
                            <td>` + data['test_list'][i].username + `</td>
                            <td>` + data['test_list'][i].obtained_marks + `</td>
                            <td>` + Duration(data['test_list'][i].required_time) + `</td>
                          </tr>`
                    }
                    table = table + '</tbody>';
                    $("#table-test").append(table);

                    $("#table-test").DataTable({
                      "responsive": true, "lengthChange": false, "autoWidth": false,
                      "buttons": ["excel", "pdf"]
                    }).buttons().container().appendTo('#example1_wrapper .col-md-6:eq(0)');

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
})

function Duration(duration_string){
    var array = duration_string.split('T');
    var day = (array[0].split('P'))[1].split("D");
    var hours = array[1].split('H');
    var min = hours[1].split("M");
    var sec = min[1].split("S");
    day = parseInt(day[0]) * 24;
    hours = (parseInt(hours[0]) + day).toString();
    min = (parseInt(min[0])).toString();
    sec = (parseInt(sec[0])).toString();

    if(hours.length == 1){
        hours = '0' + hours
    }
    if(min.length == 1){
        min = '0' + min
    }
    if(sec.length == 1){
        sec = '0' + sec
    }
    return hours + ':' + min + ':' + sec;
}
