$(document).ready(function() {
    var oTable = $('#admin_list').DataTable({
        "columnDefs": [
            { "orderable": false, "targets": 7 }
        ],
        "language": {
            'paginate': {
                'previous': '<span class="fa fa-chevron-left"></span>',
                'next': '<span class="fa fa-chevron-right"></span>'
            },
            "lengthMenu": '<div class="d-flex align-items-center">Display'+
              '<div class="input-group input-group-sm my-3 mx-2 p-0 border border-dark" style="border-radius: 20px;">'+
                '<select class="form-select border border-0" style="border-radius: 20px;">'+
                '<option value="5">5</option>'+
                '<option value="10">10</option>'+
                '<option value="20">20</option>'+
                '<option value="30">30</option>'+
                '<option value="50">50</option>'+
                '<option value="-1">All</option>'+
                '</select></div> Results</div>',
        },
        // Disable DataTables default search input
        "dom": 'rt<"bottom"flp><"clear">',
        "initComplete": function(settings, json) {
            // Bind custom search input to DataTable search
            $('#search_input').on('keyup change', function() {
                oTable.search(this.value).draw();
            });

            // Clear button logic
            $('#clear_btn').on('click', function() {
                $('#search_input').val('');
                $(this).css('display', 'none');
                oTable.search('').draw();
            });
        }
    });

    // Custom function to show/hide the clear button
    $('#search_input').on('input', function() {
        hasText();
    });

    // Custom category filter logic
    $('#category_list').on('change', function() {
        var selectedValue = $(this).val();
        if (selectedValue === 'all') {
            oTable.search('').columns().search('').draw();
        } else {
            oTable.columns(8).search(selectedValue).draw();
        }
    });

    // Clear button visibility based on input content
    function hasText() {
        let text = document.getElementById("search_input").value;
        let clearBtn = document.getElementById("clear_btn");
        clearBtn.style.display = text.trim() !== "" ? "block" : "none";
    }

    // Optional: Automatically close alerts after 3 seconds
    setTimeout(function() {
        bootstrap.Alert.getOrCreateInstance(document.querySelector(".alert")).close();
    }, 3000);
});



  $(document).ready(function () {
    // Handle the click event on the eye icon button
    $('.btn-info').on('click', function () {
        var adminId = $(this).data('admin-id');
        
        // Perform an AJAX request to get admin details
        $.ajax({
            url: `/api/admins/${adminId}/`, // Update this URL based on your API endpoint
            type: 'GET',
            success: function (data) {
                // Create HTML content for the modal
                var modalContent = `
                    <p>Admin ID: ${data.admin_id}</p>
                    <p>Full Name: ${data.admin_first_name} ${data.admin_last_name}</p>
                    <p>Email Address: ${data.admin_email}</p>
                    <p>Gender: ${data.admin_gender}</p>
                    <p>Date of Birth: ${data.admin_dob}</p>
                    <p>Phone No.: ${data.admin_contact}</p>
                    <p>Address: ${data.admin_address}</p>
                `;
                
                // Update the modal body with the admin details
                $('#adminDetailsBody').html(modalContent);
                // Show the modal
                $('#AdminModal').modal('show');
            },
            error: function (error) {
                console.log('Error fetching admin details:', error);
            }
        });
    });
});
