function SessionManagement(document) {
    var RP_MESSAGE_FORMAT_ERROR = 'incorrect data format';

    function _calculate_session_state(client_id, origin, op_browser_state, salt) {
        var res = sjcl.hash.sha256.hash(client_id + ' ' + origin + ' ' + op_browser_state + ' ' + salt);
        return sjcl.codec.hex.fromBits(res) + "." + salt;
    }

    function isBlank(str) {
        return (str.trim().length === 0);
    }

    function validate_rp_data_format(rpData) {
        var rpDataParts = rpData.split(" ");
        if (rpDataParts.length !== 2) {
            throw RP_MESSAGE_FORMAT_ERROR;
        }
        if (isBlank(rpDataParts[0]) || isBlank(rpDataParts[1])) {
            throw RP_MESSAGE_FORMAT_ERROR;
        }

        var rpSessionStateParts = rpDataParts[1].split(".");
        if (rpSessionStateParts.length !== 2) {
            throw RP_MESSAGE_FORMAT_ERROR;
        }
        if (isBlank(rpSessionStateParts[0]) || isBlank(rpSessionStateParts[1])) {
            throw RP_MESSAGE_FORMAT_ERROR;
        }
    }

    function _get_client_id(rpData) {
        validate_rp_data_format(rpData);
        var rpDataParts = rpData.split(" ");
        return rpDataParts[0];
    }

    function _get_session_state(rpData) {
        validate_rp_data_format(rpData);
        var rpDataParts = rpData.split(" ");
        return rpDataParts[1];
    }

    function _get_salt(rpData) {
        return _get_session_state(rpData).split(".")[1];
    }

    function _get_op_browser_state() {
        var cookies = document.cookie.split(';');
        var opbs = '';
        cookies.forEach(function(c) {
            var cookieName = c.split("=")[0].trim();
            var cookieValue = c.split("=")[1];
            if (cookieName === "Current-User") {
                opbs = JSON.parse(decodeURIComponent(cookieValue)).userId;
            }
        });

        return opbs;
    }

    function buildMessageHandler(expected_origin, expected_client) {
        return function handleMessage(e) {
            // This method follows the implementation described in the OIDC session
            // management spec http://openid.net/specs/openid-connect-session-1_0.html#OPiframe
            try {
                var client_id = _get_client_id(e.data);
                var rp_session_state = _get_session_state(e.data);
                var salt = _get_salt(e.data);
            } catch (err) {
                e.source.postMessage('error', e.origin);
                return;
            }

            if (expected_origin !== e.origin) {
                e.source.postMessage('error', e.origin);
                return;
            }
            if (expected_client !== client_id) {
                e.source.postMessage('error', e.origin);
                return;
            }

            var opbs = _get_op_browser_state();
            var op_session_state = _calculate_session_state(client_id, e.origin, opbs, salt);

            if (rp_session_state === op_session_state) {
                e.source.postMessage('unchanged', e.origin);
            } else {
                e.source.postMessage('changed', e.origin);
            }
        }
    }

    return {
        _calculate_session_state: _calculate_session_state,
        _get_client_id: _get_client_id,
        _get_session_state: _get_session_state,
        _get_salt: _get_salt,
        _get_op_browser_state: _get_op_browser_state,
        buildMessageHandler: buildMessageHandler
    };
}