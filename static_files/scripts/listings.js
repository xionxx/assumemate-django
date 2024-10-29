$(document).ready(function() {
    var oTable = $('#admin_list').DataTable({
        "columnDefs": [
            { "orderable": false, "targets": 5 } // Disable sorting on the 'Action' column
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
        "initComplete": function() {
            $('#clear_btn').on('click', function() {
                $('#search_input').val('');
                $('#clear_btn').hide();
                oTable.search('').draw();
            });

            $('#search_input').on('keyup change', function() {
                var searchValue = $(this).val();
                oTable.search(searchValue).draw();
                if (searchValue.trim() !== "") {
                    $('#clear_btn').show();
                } else {
                    $('#clear_btn').hide();
                }
            });
        }
    });

    // Handle category filtering
    $('#category_list').on('change', function () {
        var selectedValue = $(this).val().toLowerCase();

        // Reset the table to show all rows
        oTable.rows().every(function() {
            var row = this.node();
            $(row).show(); // Show all rows first
        });
        
        if (selectedValue !== 'all') {
            // Filter rows based on selected category
            oTable.rows().every(function() {
                var row = this.node();
                var category = $(row).data('category').toLowerCase();
                if (category !== selectedValue) {
                    $(row).hide(); // Hide non-matching rows
                }
            });
        }
        oTable.draw(); // Refresh the table
    });

    // Auto-hide alerts after 3 seconds
    setTimeout(function() {
        bootstrap.Alert.getOrCreateInstance(document.querySelector(".alert")).close();
    }, 3000);
});
