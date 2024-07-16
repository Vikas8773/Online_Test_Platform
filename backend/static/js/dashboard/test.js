$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#test-id").val();
    var url = "/api/test";
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

                    var status = data['status']
                    if(status == null){
                        var button = `
                            <div class="text-right">
                              <form action="/instruction" method="post">
                                <input type="hidden" name="csrfmiddlewaretoken" value="`
                                        + token +
                                    `">
                                <input type="hidden" id="id" name="id" value="`
                                        + data['test'].id +
                                    `" class="d-none" readonly>
                                <button type="submit" class="btn btn-success px-4">Start</a>
                              </form>
                            </div>
                        `
                    }
                    else if(status){
                        var button = `
                            <div class="text-right">
                                <a href="/result/` + id + `" class="btn btn-success px-4" >Result</a>
                            </div>
                        `
                    }
                    else{
                        var button = `
                            <div class="text-right">
                              <form action="/instruction" method="post">
                                <input type="hidden" name="csrfmiddlewaretoken" value="`
                                        + token +
                                    `">
                                <input type="hidden" id="id" name="id" value="`
                                        + data['test'].id +
                                    `" class="d-none" readonly>
                                <button type="submit" class="btn btn-success px-4">Continue</a>
                              </form>
                            </div>
                        `
                    }

                    $("#test-information-card").append(`
                        <div class="card mt-3">
                          <div class="card-header">
                            <h2 class="card-title"><b>`
                                 + data['test'].title +
                            `</b></h2>
                            `
                            + button +
                            `
                          </div>
                          <!-- /.card-header -->
                          <div class="card-body container-fluid">
                            <dl class="row">
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