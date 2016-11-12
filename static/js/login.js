$(document).ready(function () {
    $('#loginform').validate({
        rules: {
            username: {
                required: true,
                minlenght: 3
            },
            password: {
                required: true,
                minlength: 9
            }
        },
        submitHandler: function (form) {
            return true;
        }
    });
});
