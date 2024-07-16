$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var url = "/api/examine/uploaded_test_list";
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
                            data['test_list'][i].status = 'Activated'
                        }
                        else{
                            data['test_list'][i].status = 'DeActivated'
                        }
                        table = table + `
                           <tr>
                            <td>` + data['test_list'][i].title + `</td>
                            <td>` + data['test_list'][i].subject + `</td>
                            <td>` + data['test_list'][i].status + `</td>
                            <td class="">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="pb-1">
                                            <a href="/examine/test/` + data['test_list'][i].id + `" class="btn btn-success w-100">Info</a>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="pb-1">
                                            <a href="/examine/edit_test/` + data['test_list'][i].id + `" class="btn btn-primary w-100">Edit</a>
                                        </div>
                                    </div>
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