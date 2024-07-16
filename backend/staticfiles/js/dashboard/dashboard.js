$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var url = "/api/dashboard";
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
                    var testListLength = data['recent_uploaded_test_list'].length;
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
                                      <h4><b>` + data['recent_uploaded_test_list'][i].title + `</b></h4>
                                      <p>` + data['recent_uploaded_test_list'][i].subject + `</p>
                                    </div>
                                    <a href="/test/` + data['recent_uploaded_test_list'][i].id + `" class="small-box-footer">
                                      More info <i class="fas fa-arrow-circle-right"></i>
                                    </a>
                                  </div>
                                </div>`
                            )
                        }
                    }

                    var testListLength = data['in_progress_test_list'].length;
                    if(testListLength == 0){
                        $("#in_process_test").append(
                                `<p class="text-muted ml-4">No Recent Process</p>`
                            )
                    }
                    else{
                        for (var i = 0; i < testListLength; i++) {
                            $("#in_process_test").append(
                                `<div class="col-lg-3 col-6">
                                  <div class="small-box bg-danger">
                                    <div class="inner">
                                      <h4><b>` + data['in_progress_test_list'][i].title + `</b></h4>
                                      <p>` + data['in_progress_test_list'][i].subject + `</p>
                                    </div>
                                    <a href="/test/` + data['in_progress_test_list'][i].id + `" class="small-box-footer">
                                      More info <i class="fas fa-arrow-circle-right"></i>
                                    </a>
                                  </div>
                                </div>`
                            )
                        }
                    }

                    var testListLength = data['completed_test_list'].length;
                    if(testListLength == 0){
                        $("#completed_test").append(
                                `<p class="text-muted ml-4">No Recent Completed</p>`
                            )
                    }
                    else{
                        for (var i = 0; i < testListLength; i++) {
                            $("#completed_test").append(
                                `<div class="col-lg-3 col-6">
                                  <div class="small-box bg-success">
                                    <div class="inner">
                                      <h4><b>` + data['completed_test_list'][i].title + `</b></h4>
                                      <p>` + data['completed_test_list'][i].subject + `</p>
                                    </div>
                                    <a href="/test/` + data['completed_test_list'][i].id + `" class="small-box-footer">
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