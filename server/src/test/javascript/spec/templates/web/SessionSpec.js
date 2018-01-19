describe("Session", function() {
    fs = require('fs')
    sha256JS = fs.readFileSync('/Users/pivotal/workspace/uaa/server/src/main/resources/templates/web/session/sjcl.js','utf-8') // depends on the file encoding
    eval(sha256JS)
    sessionJS = fs.readFileSync('/Users/pivotal/workspace/uaa/server/src/main/resources/templates/web/session/session.js','utf-8') // depends on the file encoding
    eval(sessionJS)

    it("calculates session state", function () {
        var client_id = '1';
        var origin = 'example.com';
        var salt = 'somesalt';
        var browser_state = 'JSESSIONID_VALUE';
        ss = session_state(client_id, origin, browser_state, salt);
        expect(ss).toEqual("e53852e9aff5c750c8ba47d760e87be41e44b02697822c86d3bb9e9f61bf5e13.somesalt")
    });
});