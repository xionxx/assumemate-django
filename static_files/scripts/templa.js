$(document).ready(function() {
    // Get the current date and time
    var currentDateTime = new Date();

    // Format date as "MM/DD/YY"
    var dateOptions = { month: 'numeric', day: 'numeric', year: '2-digit' };
    var formattedDate = currentDateTime.toLocaleDateString('en-US', dateOptions);

    // Format time as "H:mm"
    var timeOptions = { hour: 'numeric', minute: 'numeric' };
    var formattedTime = currentDateTime.toLocaleTimeString('en-US', timeOptions);

    // Combine date and time
    var formattedDateTime = formattedDate + ' ' + formattedTime;

    // Display the formatted date and time
    $('#formattedDateTime').text(formattedDateTime);
});

setTimeout(function() {
    bootstrap.Alert.getOrCreateInstance(document.querySelector(".alert")).close();
  }, 3000)