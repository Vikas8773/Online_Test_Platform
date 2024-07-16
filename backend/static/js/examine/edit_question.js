$(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#question-id").val();
    var url = "/api/examine/edit_question";
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
                    $("input[name='title']").val(data['question']['title']);

                    if(data['question']['question'] != null){
                        $(".summernote-question").summernote('code', data['question']['question']);
                    }

                    if(data['question']['option_1'] != null){
                        $(".summernote-option_1").summernote('code', data['question']['option_1']);
                    }

                    if(data['question']['option_2'] != null){
                        $(".summernote-option_2").summernote('code', data['question']['option_2']);
                    }

                    if(data['question']['option_3'] != null){
                        $(".summernote-option_3").summernote('code', data['question']['option_3']);
                    }

                    if(data['question']['option_4'] != null){
                        $(".summernote-option_4").summernote('code', data['question']['option_4']);
                    }

                    $("input[name=answer][value=" + data['question']['correct_answer'] + "]").prop('checked', true);

                    if(data['question']['answer_key_description'] != null){
                        $(".summernote-answer_key_description").summernote('code', data['question']['answer_key_description']);
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

$("#add_test-form").submit(function(e) {
    e.preventDefault();

    $("#add_test-submit").attr('disabled','disabled');
    $("#add_test-loading").removeClass("d-none");

    var csrfmiddlewaretoken = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("input[name='id']").val();
    var title = Capitalize($("input[name='title']").val());

    if($(".summernote-question").summernote('isEmpty')){
        alert('Question Required..!')
        return false;
    }
    else{
        var question = $(".summernote-question").summernote('code');
    }

    if($(".summernote-option_1").summernote('isEmpty')){
        alert('Option 1 Required..!')
        return false;
    }
    else{
        var option_1 = $(".summernote-option_1").summernote('code');
    }

    if($(".summernote-option_2").summernote('isEmpty')){
        alert('Option 2 Required..!')
        return false;
    }
    else{
        var option_2 = $(".summernote-option_2").summernote('code');
    }

    if($(".summernote-option_3").summernote('isEmpty')){
        alert('Option 3 Required..!')
        return false;
    }
    else{
        var option_3 = $(".summernote-option_3").summernote('code');
    }

    if($(".summernote-option_4").summernote('isEmpty')){
        alert('Option 4 Required..!')
        return false;
    }
    else{
        var option_4 = $(".summernote-option_4").summernote('code');
    }

    var answer = $("input[name='answer']:checked").val()
    var answer_key_description = $(".summernote-answer_key_description").summernote('code');

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
                'question': question,
                'option_1': option_1,
                'option_2': option_2,
                'option_3': option_3,
                'option_4': option_4,
                'correct_answer': answer,
                'answer_key_description': answer_key_description,
           },
           success: function(data)
           {
                if(data['status']){
                    window.location.href = '/examine/question/' + data['data']['question'].id;
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





$("#add_test-form").submit(function(e) {

    e.preventDefault();

    var csrfmiddlewaretoken = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("input[name='id']").val();
    var title = Capitalize($("input[name='title']").val());

    if($(".summernote-question").summernote('isEmpty')){
        alert('Question Required..!')
        return false;
    }
    else{
        var question = $(".summernote-question").summernote('code');
    }

    if($(".summernote-option_1").summernote('isEmpty')){
        alert('Option 1 Required..!')
        return false;
    }
    else{
        var option_1 = $(".summernote-option_1").summernote('code');
    }

    if($(".summernote-option_2").summernote('isEmpty')){
        alert('Option 2 Required..!')
        return false;
    }
    else{
        var option_2 = $(".summernote-option_2").summernote('code');
    }

    if($(".summernote-option_3").summernote('isEmpty')){
        alert('Option 3 Required..!')
        return false;
    }
    else{
        var option_3 = $(".summernote-option_3").summernote('code');
    }

    if($(".summernote-option_4").summernote('isEmpty')){
        alert('Option 4 Required..!')
        return false;
    }
    else{
        var option_4 = $(".summernote-option_4").summernote('code');
    }

    var answer = $("input[name='answer']:checked").val()
    var answer_key_description = $(".summernote-answer_key_description").summernote('code');

    $("#add_test-submit").attr('disabled','disabled');
    $("#add_test-loading").removeClass("d-none");

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
                'question': question,
                'option_1': option_1,
                'option_2': option_2,
                'option_3': option_3,
                'option_4': option_4,
                'correct_answer': answer,
                'answer_key_description': answer_key_description,
           },
           success: function(data)
           {
                if(data['status']){
                    window.location.href = '/examine/question/' + data['data']['question'].id;
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