$("#register_reviewer").click(function (event) {
    event.preventDefault();

    var baseURL = $(this).attr("action");

    var e_mail = $("#emailaddress").val();
    var f_name = $("#firstname").val().trim();
    var l_name = $("#lastname").val().trim();
    var gender = $("input[name='gender']:checked").val();
    var b_day = $("#dob").val();
    var phone_num = $("#mobile").val();
    var add = $("#address").val();
    var csrf_token = $("input[name='csrfmiddlewaretoken']").val();
    
    var nameRegex = /^[a-zA-Z\s]+$/;
    var emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    var mobileRegex = /^(\+?63|0)9\d{9}$/;

    if(l_name == null || l_name === '' || f_name == null || f_name === '') {
        $("#msg").text("Firstname or Lastname cannot be empty.")
            .addClass('alert alert-danger').removeClass('alert-warning').fadeIn(0).fadeOut(3000);
        return false;
    }

    if (!nameRegex.test(f_name) || !nameRegex.test(l_name)) {
        $("#msg").text("Special characters are not allowed in Firstname or Lastname.")
            .addClass('alert alert-danger').removeClass('alert-warning').fadeIn(0).fadeOut(3000);
        return false;
    }

    if (/\d/.test(f_name) || /\d/.test(l_name)) {
        $("#msg").text("First or Last names cannot contain digits.")
            .addClass('alert alert-danger').removeClass('alert-warning').fadeIn(0).fadeOut(3000);
        return false;
    }

    if (!emailRegex.test(e_mail)) {
        $("#msg").text("Invalid Gmail email format.")
            .addClass('alert alert-danger').removeClass('alert-warning').fadeIn(0).fadeOut(3000);
        return false;
    }
    
    if (!mobileRegex.test(phone_num)) {
        $("#msg").text("Enter Valid Philippine Number").addClass('alert alert-danger').removeClass('alert-warning').fadeIn(0).fadeOut(3000);
        return false;
    } 

    $.post(baseURL, {
        email: e_mail,
        fname: f_name,
        lname: l_name,
        gender: gender,
        bday: b_day,
        phone: phone_num,
        address: add,
        csrfmiddlewaretoken: csrf_token,
    }, function (response) {
        console.log(response)
        if (response.status == 200) {
            console.log('Status: ' + response.status)
            console.log('Message: ' + response.message)
        } else {
            console.log('Status: ' + response.status)
            console.log('Message: ' + response.message)
        }
    });
    
});
