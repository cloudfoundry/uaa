// validatePassword contains the logic for client side password validation.
// It is passed in rule threshold information and then sets up watchers to check
// the password as it is typed in. It then compares the password to the value
// of the confirmation password.
// This function is to be used in with the html from pw_validation.html
function validatePassword(specialCount, uppercaseCount, lowercaseCount,
                            numberCount, lengthCount, passwordField,
                            confirmPasswordField) {
    // Set the values for the password policy requirements into the html.
    document.getElementById("special-count").innerHTML=''+specialCount+'';
    document.getElementById("uppercase-count").innerHTML=''+uppercaseCount+'';
    document.getElementById("lowercase-count").innerHTML=''+lowercaseCount+'';
    document.getElementById("number-count").innerHTML=''+numberCount+'';
    document.getElementById("length-count").innerHTML=''+lengthCount+'';

    // Hide rules that aren't set or set to zero.
    if ( specialCount === 0 ) {$('#special-req').hide();}
    if ( uppercaseCount === 0 ) {$('#uppercase-req').hide();}
    if ( lowercaseCount === 0 ) {$('#lowercase-req').hide();}
    if ( numberCount === 0 ) {$('#number-req').hide();}
    if ( lengthCount === 0 ) {$('#length-req').hide();}

    // Create a simple boolean to check if no policy is set.
    var noRules = ((specialCount === 0) && (uppercaseCount === 0) &&
                    (lowercaseCount === 0) && (numberCount === 0) &&
                    (lengthCount === 0));
    // If no policy, make sure it stays hidden.
    if (noRules == true) {$('#password-requirements').hide();}

    // validateField is a helper function.
    // Depending on the current conditional, it will set the CSS class for the
    // corresponding 'html_field' text to either 'text-success' or 'text-danger'
    function validateField(errorCase, htmlField) {
        if ( errorCase === true ) {
            $(htmlField).removeClass('text-success').addClass('text-danger');
        } else {
            $(htmlField).removeClass('text-danger').addClass('text-success');
        }
    }

    // compareNewPasswords is a helper function.
    // It will look at the values of passwordField and confirmPasswordField
    // and compare them. If equal, it will set a placeholder text to read 'DO'.
    // Else, it will be set to 'DO NOT'.
    // This placeholder text will either fit in a broader text to either read:
    // "Passwords 'DO/ DO NOT' match."
    function compareNewPasswords() {
        // Get the password value.
        var pw = $("input[type='password'][name='" + passwordField + "']").val();
        // Get the confirm password value.
        var confirmPw = $("input[type='password'][name='" + confirmPasswordField + "']").val();
        if (pw === confirmPw) {
            document.getElementById("match-passwords").innerHTML='DO';
        } else {
            document.getElementById("match-passwords").innerHTML='DO NOT';
        }
    }

    // Setup password validator.
    $("input[type='password'][name='" + passwordField + "']").keyup(function() {
        // Compare new passwords.
        compareNewPasswords();

        // If no rules, no need to do anything else.
        if ( noRules == true ) {return;}

        // Get the password value.
        var pw = $(this).val();

        // Validate the length of the password.
        validateField( ( pw.length < lengthCount ), '#length-req');

        // Validate the number of special characters.
        validateField(( ( pw.length - pw.replace( /[^0-9a-zA-Z]/g, '' ).length ) < specialCount ), '#special-req');

        // Validate the number of lowercase letters
        validateField(( (pw.length - pw.replace(/[a-z]/g, '').length) < lowercaseCount ), '#lowercase-req');

        // Validate the number of uppercase letters
        validateField(( (pw.length - pw.replace(/[A-Z]/g, '').length) < uppercaseCount ), '#uppercase-req');

        // Validate the number of digits
        validateField(( (pw.length - pw.replace(/[0-9]/g, '').length) < numberCount ), '#number-req');
    }).focus(function() {  // When the user clicks into the password field.
        // If no rules, no need to do anything.
        if ( noRules === true ) {return;}
        // Else, show the requirements box.
        $('#password-requirements').show();
    }).blur(function() {  // When the user clicks out of the password field.
        // If no rules, no need to do anything.
        if ( noRules === true ) {return;}
        // Else, hide the requirements box.
        $('#password-requirements').hide();
    });

    // Setup matcher for password confirmation.
    $("input[type='password'][name='" + confirmPasswordField + "']").keyup(function() {
        compareNewPasswords();
    }).focus(function() {  // When the user clicks into the confirm password field.
        // Show the confirmation requirement box.
        $('#pw-confirm-requirement').show();
    }).blur(function() {  // When the user clicks out of the password field.
        // Hide the confirmation requirement box.
        $('#pw-confirm-requirement').hide();
    });
}