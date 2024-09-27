function clear_input() {
    document.getElementById("stock_form").reset();
}

document.addEventListener('DOMContentLoaded', function () {
    var myModal = new bootstrap.Modal(document.getElementById('exampleModal'));

    myModal._element.addEventListener('hidden.bs.modal', function () {
        clear_input();
    });
});

$(document).ready(function () {
    $("#searchBtn").click(function (event) {
        event.preventDefault();

        var id = $('#search_id').val().trim();

        if(id !== '') {
            $.ajax({
                type: 'POST',
                url: '/products/search',
                data: {
                    'search_id': id,
                    'csrfmiddlewaretoken': $('input[name=csrfmiddlewaretoken]').val(),
                },
                dataType: 'json',
                success: function (data) {
                    if ('error' in data) {
                        window.alert('Error: Product not found');
                        clear_input();
                    } else {
                        $('#prod_deets').val(data.brand + ' ' + data.name + ' ' + data.size);
                        $('#prod_price').val(data.price);
                    }
                }
            });
        } else {
            window.alert('Enter product ID');
        }
    });

    var oTable = $('#inv_item').DataTable({
        // Disable DataTables search input
       "columnDefs": [
           { "orderable": false, "targets": 5 }
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
 
       //"dom": '<"top"f>rt<"bottom"flp><"clear">', // Place the custom search input at the top
             "initComplete": function(settings, json) {
                 // Bind existing input to DataTable search
                 $('#clear_btn').on('click', function() {
                   $('#search_input').val('');
                   $('#clear_btn').css('display', 'none');
 
                   oTable.search('').draw();
               });
 
                 $('#search_input').on('keyup change', function() {
                   oTable.search(this.value).draw();
                 });
               }
   });
});

function hasText() {
    let text = document.getElementById("search_input").value;
    let clearBtn = document.getElementById("clear_btn");
    
    if (text.trim() !== "") {
        clearBtn.style.display = "block";
    } else {
        clearBtn.style.display = "none";
    }
}