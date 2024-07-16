$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#question-id").val();
    var url = "/api/examine/question";
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
                    if(data['question'].answer_key_description == null){
                        data['question'].answer_key_description = '-'
                    }

                    $("#test-information-card").append(`
                        <div class="card mt-3">
                          <div class="card-header">
                            <h2 class="card-title"><b>`
                                 + data['question'].title +
                            `</b></h2>
                            <div class="text-right">
                                <a href="/examine/test/`+ data['question'].test_id +`" class="btn btn-danger">Back</a>
                            </div>
                          </div>
                          <!-- /.card-header -->
                          <div class="card-body container-fluid">
                            <dl class="row">
                              <dt class="col-sm-4">Id</dt>
                              <dd class="col-sm-8">`+ data['question'].id +`</dd>

                              <dt class="col-sm-4">Author</dt>
                              <dd class="col-sm-8">`+ data['question'].author +`</dd>

                              <dt class="col-sm-4">Test Name</dt>
                              <dd class="col-sm-8">`+ data['question'].test +`</dd>

                              <hr>

                              <dt class="col-sm-4">Title</dt>
                              <dd class="col-sm-8">`+ data['question'].title +`</dd>

                              <dt class="col-sm-4">Question</dt>
                              <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['question'].question +`</dd>

                              <dt class="col-sm-4">Option 1</dt>
                              <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['question'].option_1 +`</dd>

                              <dt class="col-sm-4">Option 2</dt>
                              <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['question'].option_2 +`</dd>

                              <dt class="col-sm-4">Option 3</dt>
                              <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['question'].option_3 +`</dd>

                              <dt class="col-sm-4">Option 4</dt>
                              <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['question'].option_4 +`</dd>

                              <hr>

                              <dt class="col-sm-4">Correct Answer</dt>
                              <dd class="col-sm-8"> Option-`+ data['question'].correct_answer +`</dd>

                              <dt class="col-sm-4">Answer Description</dt>
                              <dd class="col-sm-8 container-fluid" style="overflow: auto;">`+ data['question'].answer_key_description +`</dd>

                              <hr>

                              <dt class="col-sm-4">Created On</dt>
                              <dd class="col-sm-8">`+ DateTime(data['question'].created_on) +`</dd>

                              <dt class="col-sm-4">Modified On</dt>
                              <dd class="col-sm-8">`+ DateTime(data['question'].modified_on) +`</dd>

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

function DateTime(datetime){
    var date = datetime.split('T');
    var time = date[1].split('Z');
    return 'Date: ' + date[0] + ' Time: ' + time[0]
}
