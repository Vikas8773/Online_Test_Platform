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

                    $("#test-information-card").append(`
                            <dl class="row">
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
                            </dl>
                    `)
                    return true;
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = "/error?error=400 - BAD REQUEST&message="+data['data']['message'];
                    }
                    return false;
                }
           },
            error: function (data) {
                console.log('An error occurred.');
                console.log(data);
            },
         });
         return false;
})

$("#start_exam_form").submit(function(e) {
    $("#start_exam").attr('disabled','disabled');

    var csrfmiddlewaretoken = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("input[name='id']").val();

    e.preventDefault();
    var form = $(this);
    var url = form.attr('action');
    var type = form.attr('method');
    $.ajax({
           async: true,
           type: type,
           url: url,
           data: {
                'csrfmiddlewaretoken': csrfmiddlewaretoken,
                'id': id
           },
           success: function(data)
           {
                if(data['status']){
					window.location.href = '/exam';
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = '/error?error=400 - BAD REQUEST&message=' + data['data']['message'];
                    }
                    else{
                        $("#start_exam").removeAttr('disabled');
                    }
                }
           },
            error: function (data) {
                console.log('An error occurred.');
                console.log(data);
            },
         });
    return false;
});

$("#agree_box").on('change', function(){
    if($("#agree_box").prop('checked') == true){
        $("#start_exam").prop('disabled', false);
    }
    else{
        $("#start_exam").prop('disabled', true);
    }
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