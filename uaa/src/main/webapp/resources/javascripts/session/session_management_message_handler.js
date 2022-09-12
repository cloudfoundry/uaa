var sm = SessionManagement(document);
var clientId;
var messageOrigin;

document.addEventListener('DOMContentLoaded', function () {
    clientId = document.getElementById("clientId").value;
    messageOrigin = document.getElementById("messageOrigin").value;

    window.addEventListener('message', sm.buildMessageHandler(messageOrigin, clientId), false);
});
