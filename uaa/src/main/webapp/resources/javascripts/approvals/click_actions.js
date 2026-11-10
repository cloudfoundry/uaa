$(document).ready(function() {
    $('.revoke-link').click(function(e) {
        e.preventDefault();
        var clientId = $(this).attr('data-client-id');
        $(document.getElementById(clientId + '-scrim')).show();
    });

    $('.revocation-cancel').click(function(e) {
        e.preventDefault();
        $(this).parents('.revocation-scrim').hide();
    });
});
