document.addEventListener('DOMContentLoaded', function () {
    let element = document.getElementById("last_login_time");
    if (element) {
        var lastLogin = element.getAttribute("last-login-success-time");
        document.getElementById("last_login_time").innerHTML =
            new Date(Number(lastLogin)).toLocaleString();
    }
});