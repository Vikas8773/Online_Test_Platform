$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var url = "/api/exam_list";
    var type = "GET";
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
                    var data = data['data'];
                    var testListLength = data['test_list'].length;

                    var table = '<tbody id="table-body">';

                    for (var i = 0; i < testListLength; i++) {
                        if(data['test_list'][i].status == true){
                            data['test_list'][i].status = 'Submitted'
                        }
                        else if(data['test_list'][i].status == false){
                            data['test_list'][i].status = 'In Progress'
                        }
                        else{
                            data['test_list'][i].status = 'Not Attempted'
                        }
                        table = table + `
                           <tr>
                            <td>` + data['test_list'][i].name + `</td>
                            <td>` + data['test_list'][i].subject + `</td>
                            <td>` + data['test_list'][i].status + `</td>
                            <td>
                                <div class="pb-1">
                                    <a href="/test/` + data['test_list'][i].id + `" class="btn btn-success w-100">Info</a>
                                </div>
                            </td>
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