$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#test-id").val();
    var url = "/api/result";
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
                    data = data['data']
                    $("#result-card").html(`
                        <div class="card mt-3">
                            <div class="card-header">
                              <h2 class="card-title"><b>Result</b></h2>
                            </div>
                            <!-- /.card-header -->
                            <div class="card-body container-fluid">
                              <dl class="row">
                                <dt class="col-sm-4">Title</dt>
                                <dd class="col-sm-8">`+ data['test'].title +`</dd>

                                <dt class="col-sm-4">Subject</dt>
                                <dd class="col-sm-8">`+ data['test'].subject +`</dd>

                                <dt class="col-sm-4">Obtained Marks</dt>
                                <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['obtained_marks'] +`</dd>

                                <dt class="col-sm-4">Total Marks</dt>
                                <dd class="col-sm-8">`+ data['total_marks'] +`</dd>

                                <dt class="col-sm-4">No. of Correct Questions</dt>
                                <dd class="col-sm-8">`+ data['correct_questions'] +`</dd>

                                <dt class="col-sm-4">No. of Wrong Questions</dt>
                                <dd class="col-sm-8">`+ data['wrong_questions'] +`</dd>

                                <dt class="col-sm-4">No. of Unsolved Questions</dt>
                                <dd class="col-sm-8">`+ data['unsolved_questions'] +`</dd>
                              </dl>
                            </div>
                          </div>
                    `)
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
