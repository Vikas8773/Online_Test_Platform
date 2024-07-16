$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#test-id").val();
    var url = "/api/examine/test";
    var type = "GET";
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
                    data = data['data']
                    if(data['test'].description == null){
                        data['test'].description = '-'
                    }

                    if(data['test'].from_date == null){
                        data['test'].from_date = '-'
                    }
                    else{
                        data['test'].from_date = DateTime(data['test'].from_date)
                    }

                    if(data['test'].till_date == null){
                        data['test'].till_date = '-'
                    }
                    else{
                        data['test'].till_date = DateTime(data['test'].till_date)
                    }

                    if(data['test'].status == true){
                        data['test'].status = 'Activated'
                    }
                    else{
                        data['test'].status = 'DeActivated'
                    }

                    $("#test-information-card").append(`
                        <div class="card mt-3">
                          <div class="card-header">
                            <h2 class="card-title"><b>`
                                 + data['test'].title +
                            `</b></h2>
                            <div class="text-right">
                                <div class="text-right">
                                  <a href="/examine/result_list/`+ data['test'].id +`" class="btn btn-success">Results</a>
                                  <a href="/examine/edit_test/`+ data['test'].id +`" class="btn btn-primary">Edit</a>
                                </div>
                            </div>
                          </div>
                          <!-- /.card-header -->
                          <div class="card-body container-fluid">
                            <dl class="row">
                              <dt class="col-sm-4">Id</dt>
                              <dd class="col-sm-8">`+ data['test'].id +`</dd>

                              <dt class="col-sm-4">Author</dt>
                              <dd class="col-sm-8">`+ data['test'].author +`</dd>

                              <dt class="col-sm-4">Title</dt>
                              <dd class="col-sm-8">`+ data['test'].title +`</dd>

                              <dt class="col-sm-4">Subject</dt>
                              <dd class="col-sm-8">`+ data['test'].subject +`</dd>

                              <dt class="col-sm-4">Description</dt>
                              <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['test'].description +`</dd>

                              <dt class="col-sm-4">Total Questions</dt>
                              <dd class="col-sm-8">`+ data['test'].total_questions +`</dd>

                              <dt class="col-sm-4">Marks Per Question</dt>
                              <dd class="col-sm-8">`+ data['test'].marks_per_question +`</dd>

                              <dt class="col-sm-4">Total Time</dt>
                              <dd class="col-sm-8">`+ Duration(data['test'].total_time) +`</dd>

                              <dt class="col-sm-4">From Date</dt>
                              <dd class="col-sm-8">`+ data['test'].from_date +`</dd>

                              <dt class="col-sm-4">Till date</dt>
                              <dd class="col-sm-8">`+ data['test'].till_date +`</dd>

                              <dt class="col-sm-4">Status</dt>
                              <dd class="col-sm-8">`+ data['test'].status +`</dd>

                              <dt class="col-sm-4">Created On</dt>
                              <dd class="col-sm-8">`+ DateTime(data['test'].created_on) +`</dd>

                              <dt class="col-sm-4">Modified On</dt>
                              <dd class="col-sm-8">`+ DateTime(data['test'].modified_on) +`</dd>

                            </dl>
                          </div>
                        </div>
                    `)

                    var table = '<tbody id="table-body">';

                    var questionList = data['question_list']
                    var questionListLength = questionList.length

                    for(i = 0; i < questionListLength; i++){
                        table = table + `
                          <tr>
                            <td>` + questionList[i].title + `</td>
                            <td>
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="pb-1">
                                            <a href="/examine/question/` + questionList[i].id + `" class="btn btn-success w-100">Info</a>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="pb-1">
                                            <a href="/examine/edit_question/` + questionList[i].id + `" class="btn btn-primary w-100">Edit</a>
                                        </div>
                                    </div>
                                </div>
                            </td>
                          </tr>`
                    }
                    table = table + "</tbody>"

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

function DateTime(datetime){
    var date = datetime.split('T');
    var time = date[1].split('Z');
    return 'Date: ' + date[0] + ' Time: ' + time[0]
}