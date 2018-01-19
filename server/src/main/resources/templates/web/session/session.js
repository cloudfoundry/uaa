function session_state(client_id, origin, browser_state, salt) {
    var res = sjcl.hash.sha256.hash(client_id + ' ' + origin + ' ' + browser_state + ' ' + salt);
    return  sjcl.codec.hex.fromBits(res) + "." + salt;
}