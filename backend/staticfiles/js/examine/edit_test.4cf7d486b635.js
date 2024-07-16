$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#test-id").val();
    var url = "/api/examine/edit_test";
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
                    $("input[name='title']").val(data['test']['title']);
                    $("input[name='subject']").val(data['test']['subject']);

                    if(data['test']['description'] != null){
                        $(".summernote-description").summernote('code', data['test']['description']);
                    }

                    $("input[name='total_questions']").val(data['test']['total_questions']);
                    $("input[name='marks_per_question']").val(data['test']['marks_per_question']);
                    $("input[name='total_time']").val(Duration(data['test']['total_time']));

                    if(data['test']['from_date'] != null){
                        var datetime = DateTimeChange(data['test']['from_date'])
                        $("input[name='from_date_date']").val(datetime[0]);
                        $("input[name='from_date_time']").val(datetime[1]);
                    }

                    if(data['test']['till_date'] != null){
                        var datetime = DateTimeChange(data['test']['till_date'])
                        $("input[name='till_date_date']").val(datetime[0]);
                        $("input[name='till_date_time']").val(datetime[1]);
                    }

                    if(data['test']['status'])
                        $("input[name='status']").prop("checked", true);
                    else
                        $("input[name='status']").prop("checked", false);
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

function DateTimeChange(datetime){
    var date = datetime.split('T');
    var time = date[1].split('Z');

    date = date[0].split('-')
    date = date[1] + '/' + date[2] + '/' + date[0]

    time = time[0].split(':')
    time = convert_time(time[0] + ':' + time[1])

    return [date, time]
}

function convert_time (time) {
  time = time.toString ().match (/^([01]\d|2[0-3])(:)([0-5]\d)(:[0-5]\d)?$/) || [time];
  if (time.length > 1) {
    time = time.slice (1);
    time[5] = +time[0] < 12 ? ' AM' : ' PM';
    time[0] = +time[0] % 12 || 12;
  }
  return time.join ('');
}

$("#add_test-form").submit(function(e) {
    $("#add_test-submit").attr('disabled','disabled');
    $("#add_test-loading").removeClass("d-none");

    var csrfmiddlewaretoken = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("input[name='id']").val();
    var title = Capitalize($("input[name='title']").val());
    var subject = Capitalize($("input[name='subject']").val());
    var description = $(".summernote-description").summernote('code');
    var total_questions = $("input[name='total_questions']").val();
    var marks_per_question = $("input[name='marks_per_question']").val();
    var total_time = $("input[name='total_time']").val();
    var from_date_date = $("input[name='from_date_date']").val();
    var from_date_time = $("input[name='from_date_time']").val();
    var till_date_date = $("input[name='till_date_date']").val();
    var till_date_time = $("input[name='till_date_time']").val();
    var status = $("input[name='status']").prop("checked");

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
                'id': id,
                'title': title,
                'subject': subject,
                'description': description,
                'total_questions': total_questions,
                'marks_per_question': marks_per_question,
                'total_time': total_time,
                'from_date_date': from_date_date,
                'from_date_time': from_date_time,
                'till_date_date': till_date_date,
                'till_date_time':till_date_time,
                'status': status
           },
           success: function(data)
           {
                if(data['status']){
                    window.location.href = '/examine/test/' + data['data']['test'].id;
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = '/error?error=400 - BAD REQUEST&message=' + data['data']['message'];
                    }
                    else{
                        $("#add_test-submit").removeAttr('disabled');
                        $("#add_test-loading").addClass("d-none");
                        $("#add_test-msg").html(data['data']['message']);
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

function Capitalize(string){
    strLength = string.length;
    var str = '';
    for(i=0; i<strLength; i++){
        if(i == 0){
            str = str + string[i].toUpperCase()
        }
        else{
            str = str + string[i]
        }
    }
    return str;
}
