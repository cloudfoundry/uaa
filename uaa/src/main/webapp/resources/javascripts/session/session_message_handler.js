function handleMessage(e) {
    var origin = document.getElementById("messageOrigin").value;
    var messageOrigin = e.origin === 'null' ? null : e.origin;
    if ((messageOrigin || 'file://') !== origin) return;

    try {
        var messageTokens = e.data.split(' ');
        var clientId = messageTokens[0];
        var expectedClientId = document.getElementById("clientId").value;

        if (clientId !== expectedClientId) {
            throw 'Client ID mismatch';
        }

        var lastUserId = messageTokens[1];

        var nextUserId = '~';
        var cookies = document.cookie.split(';');
        for (var i in cookies) {
            var cookieNameValue = cookies[i].split('=');
            var cookieName = cookieNameValue[0];
            if (cookieName !== 'Current-User') continue;

            var cookieValue = JSON.parse(decodeURIComponent(cookieNameValue[1]));
            nextUserId = cookieValue.userId;
            break;
        }

        var status = (nextUserId === lastUserId) ? 'unchanged' : 'changed';
        e.source.postMessage(status, messageOrigin||'*');
    } catch (err) {
        e.source.postMessage('error', messageOrigin||'*');
    }
}

document.addEventListener('DOMContentLoaded', function () {
    window.addEventListener('message', handleMessage, false);
});
