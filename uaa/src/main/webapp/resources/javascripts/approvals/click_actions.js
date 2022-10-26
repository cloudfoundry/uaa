$(document).ready(function() {
    $('.revoke-link').click(function(e) {
        e.preventDefault();
        var clientId = $(this).attr('data-client-id');
        $('#'+clientId+'-scrim').show();
    });

    $('.revocation-cancel').click(function(e) {
        e.preventDefault();
        $(this).parents('.revocation-scrim').hide();
    });
});