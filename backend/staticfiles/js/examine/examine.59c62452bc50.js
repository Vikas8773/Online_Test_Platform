$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var url = "/api/examine";
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
                    if(testListLength == 0){
                        $("#recent_uploaded_test").append(
                                `<p class="text-muted ml-4">No Recent Upload</p>`
                            )
                    }
                    else{
                        for (var i = 0; i < testListLength; i++) {
                            $("#recent_uploaded_test").append(
                                `<div class="col-lg-3 col-6">
                                  <div class="small-box bg-info">
                                    <div class="inner">
                                      <h4><b>` + data['test_list'][i].title + `</b></h4>
                                      <p>` + data['test_list'][i].subject + `</p>
                                    </div>
                                    <a href="/examine/test/` + data['test_list'][i].id + `" class="small-box-footer">
                                      More info <i class="fas fa-arrow-circle-right"></i>
                                    </a>
                                  </div>
                                </div>`
                            )
                        }
                    }

                    var questionListLength = data['question_list'].length;
                    if(questionListLength == 0){
                        $("#recent_uploaded_question").append(
                                `<p class="text-muted ml-4">No Recent Upload</p>`
                            )
                    }
                    else{
                        for (var i = 0; i < questionListLength; i++) {
                            $("#recent_uploaded_question").append(
                                `<div class="col-lg-3 col-6">
                                  <div class="small-box bg-info">
                                    <div class="inner">
                                      <h4><b>` + data['question_list'][i].title + `</b></h4>
                                      <p>` + data['question_list'][i].test + `</p>
                                    </div>
                                    <a href="/examine/question/` + data['question_list'][i].id + `" class="small-box-footer">
                                      More info <i class="fas fa-arrow-circle-right"></i>
                                    </a>
                                  </div>
                                </div>`
                            )
                        }
                    }
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