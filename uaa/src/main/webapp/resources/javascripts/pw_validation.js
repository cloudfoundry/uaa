// validatePassword contains the logic for client side password validation.
// It is passed in rule threshold information and then sets up watchers to check
// the password as it is typed in. It then compares the password to the value
// of the confirmation password.
// This function is to be used in with the html from pw_validation.html
function validatePassword(specialCount, uppercaseCount, lowercaseCount,
                            numberCount, lengthCount, passwordField,
                            confirmPasswordField, submitButton) {
    // Set the values for the password policy requirements into the html.
    document.getElementById("special-count").innerHTML=''+specialCount+'';
    document.getElementById("uppercase-count").innerHTML=''+uppercaseCount+'';
    document.getElementById("lowercase-count").innerHTML=''+lowercaseCount+'';
    document.getElementById("number-count").innerHTML=''+numberCount+'';
    document.getElementById("length-count").innerHTML=''+lengthCount+'';

    // Set markers to dictate whether or not to check a particular rule. Default to true.
    var specialCharsRule = true;
    var uppercaseRule = true;
    var lowercaseRule = true;
    var digitsRule = true;
    var lengthRule = true;

    // Hide rules that aren't set or set to zero. Set the markers to false to indicate not to check them.
    if ( specialCount === 0 ) {
        $('#special-req').hide();
        specialCharsRule = false;
    }
    if ( uppercaseCount === 0 ) {
        $('#uppercase-req').hide();
        uppercaseRule = false;
    }
    if ( lowercaseCount === 0 ) {
        $('#lowercase-req').hide();
        lowercaseRule = false;
    }
    if ( numberCount === 0 ) {
        $('#number-req').hide();
        digitsRule = false;
    }
    if ( lengthCount === 0 ) {
        $('#length-req').hide();
        lengthRule = false;
    }

    // Create a simple boolean to check if no policy is set.
    var noRules = ((specialCount === 0) && (uppercaseCount === 0) &&
                    (lowercaseCount === 0) && (numberCount === 0) &&
                    (lengthCount === 0));
    // If no policy, make sure it stays hidden.
    if (noRules == true) {$('#password-requirements').hide();}

    // validateField is a helper function.
    // Depending on the current conditional, it will set the CSS class for the
    // corresponding 'html_field' text to either 'text-success' or 'text-danger'
    // Returns whether it is valid.
    // Returns true if field is valid. Else, false.
    function validateField(errorCase, htmlField) {
        if ( errorCase === true ) {
            $(htmlField).removeClass('text-success').addClass('text-danger');
            return false;
        } else {
            $(htmlField).removeClass('text-danger').addClass('text-success');
            return true;
        }
    }

    // compareNewPasswords is a helper function.
    // It will look at the values of passwordField and confirmPasswordField
    // and compare them. If equal, it will set a placeholder text to read 'DO'.
    // Else, it will be set to 'DO NOT'.
    // This placeholder text will either fit in a broader text to either read:
    // "Passwords 'DO/ DO NOT' match."
    // Return true if passwords match; false if passwords do not match.
    function compareNewPasswords() {
        // Get the password value.
        var pw = $("input[type='password'][name='" + passwordField + "']").val();
        // Get the confirm password value.
        var confirmPw = $("input[type='password'][name='" + confirmPasswordField + "']").val();
        if (pw === confirmPw) {
            document.getElementById("match-passwords").innerHTML='DO';
            return true;
        }
        document.getElementById("match-passwords").innerHTML='DO NOT';
        return false;
    }

    // validateFields returns whether or not all available fields are valid.
    function validateFields() {
        // If no rules, no need to do anything else.
        if ( noRules == true ) {return true;}

        // Get the password value.
        var pw = $("input[type='password'][name='" + passwordField + "']").val();

        // Validate the length of the password.
        var validLength = (lengthRule ? (validateField( ( pw.length < lengthCount ), '#length-req')) : true);

        // Validate the number of special characters.
        var validSpecialChars = (specialCharsRule ? (validateField(( ( pw.length - pw.replace( /[^0-9a-zA-Z]/g, '' ).length ) < specialCount ), '#special-req')) : true);

        // Validate the number of lowercase letters
        var validLowerChars = (lowercaseRule ? (validateField(( (pw.length - pw.replace(/[a-z]/g, '').length) < lowercaseCount ), '#lowercase-req')) : true);

        // Validate the number of uppercase letters
        var validUpperChars = (uppercaseRule ? (validateField(( (pw.length - pw.replace(/[A-Z]/g, '').length) < uppercaseCount ), '#uppercase-req')) : true);

        // Validate the number of digits
        var validDigits = (digitsRule ? (validateField(( (pw.length - pw.replace(/[0-9]/g, '').length) < numberCount ), '#number-req')) : true);

        return validLength && validSpecialChars && validLowerChars && validUpperChars && validDigits;
    }

    // enableSubmitButton enables the submit button.
    function enableSubmitButton() {
        $("input[type='submit'][name='" + submitButton + "']").attr('disabled' , false);
    }

    // disableSubmitButton disables the submit button.
    function disableSubmitButton() {
        $("input[type='submit'][name='" + submitButton + "']").attr('disabled' , true);
    }

    // checkPasswords is a wrapper function.
    // It checks for equal passwords and the password rules.
    // It will show the information for each in case they are invalid
    function checkPasswords() {
        // Compare new passwords.
        var equalPw = compareNewPasswords();
        // Check if field rules are valid.
        var validatedRules = validateFields();
        if (equalPw && validatedRules) {
            // Everything is right. Enable the submit button.
            enableSubmitButton();
            // Hide password equal box.
            $('#pw-confirm-requirement').hide();
            // Hide rules box.
            $('#password-requirements').hide();
        } else if (!equalPw && validatedRules) {
            // Unequal password but valid rules.
            // Make sure the submit button is disabled.
            disableSubmitButton();
            // Show password equal box.
            $('#pw-confirm-requirement').show();
            // Hide rules box.
            $('#password-requirements').hide();
        } else if (equalPw && !validatedRules) {
            // Equal password but invalid rules.
            // Make sure the submit button is disabled.
            disableSubmitButton();
            // Hide password equal box.
            $('#pw-confirm-requirement').hide();
            // Show rules box.
            $('#password-requirements').show();
        } else {
            // Unequal password AND invalid rules.
            // Make sure the submit button is disabled.
            disableSubmitButton();
            // Show password equal box.
            $('#pw-confirm-requirement').show();
            // Show rules box.
            $('#password-requirements').show();
        }
    }

    // Setup password validator.
    $("input[type='password'][name='" + passwordField + "']").bind("change keyup", function() {
        checkPasswords();
    });

    // Setup matcher for password confirmation.
    $("input[type='password'][name='" + confirmPasswordField + "']").keyup(function() {
        checkPasswords();
    });

    // Call checkPasswords for the first time.
    checkPasswords();
}