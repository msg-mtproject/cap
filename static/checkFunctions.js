// JavaScript Document

function checkPassword1() {

    var strength_label = document.getElementById('pass_strength');

    if (testThreeWordsPassword()) {
        strength_label.innerHTML = "probably strong (3 words)";
        strength_label.style="color:blue";
    } else if (testStrongPassword()) {
        strength_label.innerHTML = "probably strong";
        strength_label.style="color:blue";
    } else if (testTwoWordsPassword()) {
        strength_label.innerHTML = "probably good (2 words)";
        strength_label.style="color:grey";
    } else if (testGoodPassword()) {
        strength_label.innerHTML = "probably good";
        strength_label.style="color:grey";
    } else {
        strength_label.innerHTML = "probably weak";
        strength_label.style="color:red";
    }
    return;
}

function testStrongPassword() {
    try {
    var password = document.getElementById('password').value;
    var patt1 = /([a-z])/;
    var test1 = patt1.test(password);
    var patt2 = /([A-Z])/;
    var test2 = patt2.test(password);
    var patt3 = /([0-9])/;
    var test3 = patt3.test(password);
    var patt4 = /([\W])/;
    var test4 = patt4.test(password);
    var test_size = (password.length >= 8);
    return (test1 && test2 && test3 && test4 && test_size);
    } catch(err) {

    }
    return;
}

function testThreeWordsPassword() {
    try {
        var password = document.getElementById('password').value;
        var patt = /([\w]{3,})([\W])([\w]{2,})([\W])([\w]{3,})/g;
        var test = patt.test(password);
        var test_size = (password.length >= 10);
        return (test && test_size);
    } catch(err) {

    }
    return;
}

function testTwoWordsPassword() {
    try {
    var password = document.getElementById('password').value;
    var patt = /([\w]{3,})([\W])([\w]{3,})/g;
    var test = patt.test(password);
    var test_size = (password.length >= 8);
    return (test && test_size);
    } catch(err) {

    }
    return;
}

function testGoodPassword() {
    try {
    var password = document.getElementById('password').value;
    var patt = /([\w][0-9]|[\w][\W])/g;
    var test1 = patt.test(password);
    var test2 = (password.length >= 8);
    return (test1 && test2);
    } catch(err) {

    }
    return;
}

function checkPassword2() {
    return;
}

function checkPassword3() {
    var passwd1 = document.getElementById('password');
    var passwd2 = document.getElementById('conf_password');
    if(passwd1.value != passwd2.value){
      alert("The password confirmation is not matching. Please, verify!");
    }
    return;
}

function checkQuestion() {
    var question = document.getElementById('security_question');
    if(question.value.length == 0){
      alert("You don't have a security question!\n" +
            "If you proceed, you will not be able to reset the password!");
    }
    if(question.value.length > 0 && question.value.length < 12){
      alert("Your security question is too small (less than 12 chars)!\n" +
            "If you proceed, this may be a security risk!");
    }
    return;
}

function checkAnswer1() {
    var question = document.getElementById('security_question');
    var answer1 = document.getElementById('answer');
    if(question.value.length > 0 && answer1.value.length == 0){
      alert("You don't have a security answer!\n" +
            "If you proceed, you will not be able to reset the password!");
    }
    if(answer1.value.length > 0 && answer1.value.length < 12){
      alert("Your security answer is too small (less than 12 chars)!\n" +
            "If you proceed, this will be a security risk!");
    }
    return;
}

function checkAnswer2() {
    var answer1 = document.getElementById('answer');
    var answer2 = document.getElementById('conf_answer');
    if(answer1.value != answer2.value){
      alert("The security answer confirmation is not matching. Please, verify!");
      return false;
    }
    if(checkPassword1() == false) {
      alert("Probably you have chosen a weak password. Please, verify!");
      return false;
    }
    return;
}


document.getElementById("password").addEventListener('input', checkPassword1);
document.getElementById("password").addEventListener('change', checkPassword2);
document.getElementById("conf_password").addEventListener('change', checkPassword3);
document.getElementById("security_question").addEventListener('change', checkQuestion);
document.getElementById("answer").addEventListener('change', checkAnswer1);
document.getElementById("conf_answer").addEventListener('change', checkAnswer2);
document.getElementById("register").addEventListener('click', checkAnswer2);
