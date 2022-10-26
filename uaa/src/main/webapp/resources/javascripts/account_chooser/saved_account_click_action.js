document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll("a[data-userId]").forEach(function (savedAccountLink) {
        savedAccountLink.addEventListener('click', function () {
            document.getElementById(savedAccountLink.getAttribute('data-userId')).submit();
        })
    })
});
