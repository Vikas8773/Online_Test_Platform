$("#add_test-form").submit(function(e) {
    $("#add_test-submit").attr('disabled','disabled');
    $("#add_test-loading").removeClass("d-none");

    var csrfmiddlewaretoken = $("input[name='csrfmiddlewaretoken']").val();
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