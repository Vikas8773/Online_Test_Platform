var last_question = null
var marks_per_question = null
var remaining_time = null
var remaining_warning = null
var total_questions = null
var total_time = null
var test = null
var active_question = 1

// Functions

$(function(){
    if(window.innerHeight == screen.height) {
        if($("#exam-screen-pause").is(":visible")){
            $("#exam-screen-pause").css("display", "none");
            $("#exam-page").css("display", "block");
        }
    }

    var token = $("input[name='csrfmiddlewaretoken']").val();
    var url = "/api/exam";
    var type = "POST";
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
                    set_paper(data);
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

function set_paper(data){
    last_question = data['details']['last_question']
    marks_per_question = data['details']['marks_per_question']
    remaining_time = data['details']['remaining_time']
    remaining_warning = data['details']['remaining_warning']
    total_questions = data['details']['total_questions']
    total_time = data['details']['total_time']

    test = data['test']

    for(var i = 0; i < test.length; i++){
        var question = test[i];
        if(question['attempted']){
            $("#question-panel").append(`
                <div class="col-3 p-1">
                    <button type="button" class="btn btn-success p-1 w-100 question-button" id="question-button-` + i + `" onclick="question_button(` + i + `)">` + question['question_number'] + `</button>
                </div>
            `)
        }
        else{
            $("#question-panel").append(`
                <div class="col-3 p-1">
                    <button type="button" class="btn btn-secondary p-1 w-100 question-button" id="question-button-` + i + `" onclick="question_button(` + i + `)">` + question['question_number'] + `</button>
                </div>
            `)
        }

        if((i+1) == last_question){
            question_block(i);
        }
    }
}

function question_block(number){
    if(number < 0){
        alert_warning("This is First Question");
        return false;
    }
    else if(number >= test.length){
        alert_warning("This is last question");
        return false;
    }
    else{
        var question = test[number]
        $("#question-block").html(`
              <div id="question">
                <span><b>Q` + (number+1) + `.</b></span> ` + question['question']+ `
              </div>
              <hr>
              <div class="mt-5" id="options">
                <div class="form-check">
                  <input class="form-check-input" type="radio" name="answer" id="answer-1" onclick="answered('` + question['id']+ `', '` + question['answer_id']+ `', 1)" value="1">
                  <label class="form-check-label" for="answer-1">
                    <div>
                        ` + question['option_1']+ `
                    </div>
                  </label>
                </div>
                <hr>
                <div class="form-check">
                  <input class="form-check-input" type="radio" name="answer" id="answer-2" onclick="answered('` + question['id']+ `', '` + question['answer_id']+ `', 2)" value="2">
                  <label class="form-check-label" for="answer-2">
                    <div>
                        ` + question['option_2']+ `
                    </div>
                  </label>
                </div>
                <hr>
                <div class="form-check">
                  <input class="form-check-input" type="radio" name="answer" id="answer-3" onclick="answered('` + question['id']+ `', '` + question['answer_id']+ `', 3)" value="3">
                  <label class="form-check-label" for="answer-3">
                    <div>
                        ` + question['option_3']+ `
                    </div>
                  </label>
                </div>
                <hr>
                <div class="form-check">
                  <input class="form-check-input" type="radio" name="answer" id="answer-4" onclick="answered('` + question['id']+ `', '` + question['answer_id']+ `', 4)" value="4">
                  <label class="form-check-label" for="answer-4">
                    <div>
                        ` + question['option_4']+ `
                    </div>
                  </label>
                </div>
              </div>
        `)

        active_question = number+1;

        if(question['attempted']){
            $("#answer-" + question['answer']).prop("checked", true);
        }
        else{
            $("#question-button-" + number).addClass('btn-danger');
        }
        return true;
    }
}

$("#previous").on('click', function(){
    question_block(active_question-2);
})

$("#next").on('click', function(){
    question_block(active_question);
})

function question_button(number){
    question_block(number);
}

function fullscreen(){
    if(window.innerHeight == screen.height) {
        if($("#exam-screen-pause").is(":visible")){
            $("#exam-screen-pause").css("display", "none");
            $("#exam-page").css("display", "block");
        }
    }
    else{
        var el = document.documentElement,
          rfs = el.requestFullscreen
            || el.webkitRequestFullScreen
            || el.mozRequestFullScreen
            || el.msRequestFullscreen
        ;
        rfs.call(el);
        if($("#exam-screen-pause").is(":visible")){
            $("#exam-screen-pause").css("display", "none");
            $("#exam-page").css("display", "block");
        }
    }
}


addEventListener("click", function() {
    fullscreen();
});

    document.addEventListener("fullscreenchange", function() {
    if($("#exam-page").is(":visible")){
            $("#exam-screen-pause").css("display", "block");
            $("#exam-page").css("display", "none");
        }
        if(window.innerHeight == screen.height) {
            fullscreen();
        }
        else{
            alert_danger("Your violating Rules. Click on Exam page other wise You Got Fired.!");
        }

    });
    document.addEventListener("mozfullscreenchange", function() {
    if($("#exam-page").is(":visible")){
                $("#exam-screen-pause").css("display", "block");
                $("#exam-page").css("display", "none");
            }
        if(window.innerHeight == screen.height) {
            fullscreen();
        }
        else{
            alert_danger("Your violating Rules. Click on Exam page other wise You Got Fired.!");
        }
    });
    document.addEventListener("webkitfullscreenchange", function() {
    if($("#exam-page").is(":visible")){
                $("#exam-screen-pause").css("display", "block");
                $("#exam-page").css("display", "none");
            }
          if(window.innerHeight == screen.height) {
            fullscreen();
        }
        else{

            alert_danger("Your violating Rules. Click on Exam page other wise You Got Fired.!");
        }
    });
    document.addEventListener("msfullscreenchange", function() {
        if($("#exam-page").is(":visible")){
                $("#exam-screen-pause").css("display", "block");
                $("#exam-page").css("display", "none");
            }
        if(window.innerHeight == screen.height) {
            fullscreen();
        }
        else{
            alert_danger("Your violating Rules. Click on Exam page other wise You Got Fired.!");
        }

    });


function alert_warning(message){
    var data = `
    <div style="position:fixed; top: 0px; left: 0px; width: 100%; z-index:9999;">
      <div class="alert alert-warning alert-dismissible show" role="alert" id="warning">
        ` + message + `
      </div>
    </div>
    `
    $("#alert-messages").html(data);
    setTimeout(function(){
        $("#alert-messages").html('');
    }, 2000)
}

function alert_success(message){
    var data = `
    <div style="position:fixed; top: 0px; left: 0px; width: 100%; z-index:9999;">
      <div class="alert alert-success alert-dismissible show" role="alert" id="warning">
        ` + message + `
      </div>
    </div>
    `
    $("#alert-messages").html(data);
    setTimeout(function(){
        $("#alert-messages").html('');
    }, 2000)
}

function alert_danger(message){
    var data = `
    <div style="position:fixed; top: 0px; left: 0px; width: 100%; z-index:9999;">
      <div class="alert alert-danger alert-dismissible show" role="alert" id="warning">
        ` + message + `
      </div>
    </div>
    `
    $("#alert-messages").html(data);
    setTimeout(function(){
        $("#alert-messages").html('');
    }, 5000)
}

function answered(question_id, answer_id, answer){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var data = {
                'question': question_id,
                'answer_id': answer_id,
                'answer': answer,
                'csrfmiddlewaretoken': token
           }
    var url = "/api/exam/answered";
    var type = "POST";
    $.ajax({
           async: true,
           type: type,
           url: url,
           data: data,
           success: function(data)
           {
                if(data['status']){
                    test[(data['data']['question_number'])-1]['answer'] = data['data']['answer']
                    test[(data['data']['question_number'])-1]['attempted'] = true

                    $("#question-button-" + ((data['data']['question_number'])-1)).removeClass('btn-danger');
                    $("#question-button-" + ((data['data']['question_number'])-1)).addClass('btn-success');

                    alert_success("Answer Saved Successfully...")
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
                alert_danger("Question is Not Saved..Try Again..!")
            },
         });
}


// Timer
var time_trigger = 5
var x = setInterval(function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var url = "/api/exam/time";
    var type = "POST";
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
                    $("#timer").html(SecConvertToTime( data['data']['time'] ));
                    remaining_time = data['data']['time'];
                    if(data['data']['time'] == 0){
                        $("#end_exam_form").submit()
                    }
                }
                else{
                    if(data['code'] == 400){
                        window.location.href = "/error?error=400 - BAD REQUEST&message="+data['data']['message'];
                    }
                }
                if(time_trigger < 5){
                    time_trigger = 5;
                    $("#time_trigger_message").html('')
                    $("#time_trigger_message").addClass("d-none");
                    $("#exam-page").removeClass("d-none");
                }
           },
            error: function (data) {
                console.log('An error occurred.');
                console.log(data);
                time_trigger = time_trigger - 1;
                if(time_trigger == 0){
                    $("#time_trigger_message").html(`<div class="container montserrat border border-dark rounded p-3 my-5" style="max-width: 480px;">
                                  <p class="text-danger text-center montserrat"><b>Internet Connection Error</b></p>
                                    <p class="text-danger text-center montserrat-alt">Check your Internet Connection or Try to Login Again</p>
                                </div>`)
                    $("#time_trigger_message").removeClass("d-none");
                    $("#exam-page").addClass("d-none");
                }
            },
         });
  },1000);

function TimeConvertToSec(time){
    time = time.split(':')
    return (Integer.parseInt(time[0])*3600) + (Integer.parseInt(time[1])*60) + Integer.parseInt(time[2])
}

function SecConvertToTime(seconds){
    var hrs = Math.floor(seconds / 3600);
    var min = Math.floor((seconds - (hrs * 3600)) / 60);
    var seconds = seconds - (hrs * 3600) - (min * 60);
    seconds = Math.round(seconds * 100) / 100

    var result = (hrs < 10 ? "0" + hrs : hrs);
    result += ":" + (min < 10 ? "0" + min : min);
    result += ":" + (seconds < 10 ? "0" + seconds : seconds);
    return result;
}

$("#end_exam_form").on('submit', function(){
    var token = $("input[name='csrfmiddlewaretoken']").val();
    var id = $("#answersheet_id").val();
    var url = "/api/exam/end";
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
                    window.location.href = "/result/" + data['data']['id'];
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
                window.location.href = "/error?error=400 - BAD REQUEST&message=Internet Connection Error or Try to LogIn Again and then submit..";
            },
         });
})

$("#end_exam_button").on('click', function(){
    $("#exam-page").addClass("d-none");
    $("#end_exam_confirm").removeClass("d-none");
})

$("#cancel_end_exam").on('click', function(){
    $("#exam-page").removeClass("d-none");
    $("#end_exam_confirm").addClass("d-none");
})