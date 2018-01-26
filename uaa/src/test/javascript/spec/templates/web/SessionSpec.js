describe("Session", function() {
    var fs = require('fs');
    eval(fs.readFileSync('src/main/webapp/resources/javascripts/session/sjcl.js','utf-8'));
    eval(fs.readFileSync('src/main/webapp/resources/javascripts/session/session.js','utf-8'));

    var sm;
    var document;

    beforeEach(function() {
        document = {};
        sm = SessionManagement(document);
    });

    describe("_calculate_session_state", function () {
        it("calculates session state", function () {
            var client_id = '1';
            var origin = 'example.com';
            var salt = 'somesalt';
            var opbs = 'user-id-1';
            var ss = sm._calculate_session_state(client_id, origin, opbs, salt);
            expect(ss).toEqual("26544311372c0e521a5dcbb8725594ba0808d169110f473bd5654e489471425c.somesalt")
        });
    });

    describe("_get_session_state", function () {
        it("gets session state from a valid rp data", function () {
            expect(sm._get_session_state("clientid sessionstate.salt")).toEqual('sessionstate.salt');
        });

        it("throws an error if data is invalid", function () {
            expect(function() {sm._get_session_state("")}).toThrow('incorrect data format');
            expect(function() {sm._get_session_state("clientidsessionstate")}).toThrow('incorrect data format');
            expect(function() {sm._get_session_state("clientid session_state salt")}).toThrow('incorrect data format');
            expect(function() {sm._get_session_state("clientid session_state")}).toThrow('incorrect data format');
            expect(function() {sm._get_session_state("clientid .salt")}).toThrow();
            expect(function() {sm._get_session_state("clientid session_state.")}).toThrow();
            expect(function() {sm._get_session_state(" session_state.salt")}).toThrow();
            expect(function() {sm._get_session_state("clientid ")}).toThrow();
            expect(function() {sm._get_session_state("clientid session_state.salt")}).not.toThrow();
        });
    });

    describe("_get_client_id", function () {
        it("gets client id from a valid rp data", function () {
            expect(sm._get_client_id("clientid sessionstate.salt")).toEqual('clientid');
        });

        it("throws an error if data is invalid", function () {
            expect(function() {sm._get_client_id("")}).toThrow('incorrect data format');
            expect(function() {sm._get_client_id("sessionstate.salt")}).toThrow('incorrect data format');
            expect(function() {sm._get_client_id("clientid session_state salt")}).toThrow('incorrect data format');
            expect(function() {sm._get_client_id("clientid session_state")}).toThrow('incorrect data format');
            expect(function() {sm._get_client_id("clientid session_state.salt")}).not.toThrow();
        });
    });

    describe("_get_salt", function () {
        it("gets salt from a valid rp data", function () {
            expect(sm._get_salt("clientid sessionstate.salt")).toEqual('salt');
        });

        it("throws an error if data is invalid", function () {
            expect(function() {sm._get_salt("")}).toThrow('incorrect data format');
            expect(function() {sm._get_salt("sessionstate.salt")}).toThrow('incorrect data format');
            expect(function() {sm._get_salt("clientid session_state salt")}).toThrow('incorrect data format');
            expect(function() {sm._get_salt("clientid session_state")}).toThrow('incorrect data format');
            expect(function() {sm._get_salt("clientid session_state.salt")}).not.toThrow();
        });
    });

    describe("_get_op_browser_state", function () {
        it("gets the Current-User cookie value", function () {
            // We cannot use JSESSIONID cookie for the op browser state because the session cookie is httponly
            // and cannot be read from javascripts, even javascripts from the same origin.
            document = { cookie: 'COOKIE1=foo; COOKIE2=bar; Current-User=%7B%22userId%22%3A%229ab2f713-7baf-4411-8067-774d126327e9%22%7D;'};
            sm = SessionManagement(document);
            expect(sm._get_op_browser_state()).toEqual("9ab2f713-7baf-4411-8067-774d126327e9");
        });

        it("returns empty string when the Current-User cookie is not present", function () {
            document = { cookie: 'COOKIE1=foo; COOKIE2=bar;'};
            sm = SessionManagement(document);
            expect(sm._get_op_browser_state()).toEqual("");
        });
    });

    describe("building a message handler", function () {
        describe("when a message is received with an unexpected client id", function () {
            it("replies with an error", function () {
                sm = SessionManagement({});
                var handler = sm.buildMessageHandler("expectedOrigin", "expectedClient");
                var postMessageSpy = jasmine.createSpy('postMessageSpy');

                handler({
                    data: 'otherclientid hash.salt',
                    origin: 'expectedOrigin',
                    source: {postMessage: postMessageSpy}
                });

                expect(postMessageSpy).toHaveBeenCalledWith('error', 'expectedOrigin');
            });
        });

        describe("when a message is received with an unexpected origin", function () {
            it("replies with an error", function () {
                sm = SessionManagement({});
                var handler = sm.buildMessageHandler("expectedOrigin", "expectedClient");
                var postMessageSpy = jasmine.createSpy('postMessageSpy');

                handler({
                    data: 'expectedClient hash.salt',
                    origin: 'badOrigin',
                    source: {postMessage: postMessageSpy}
                });

                expect(postMessageSpy).toHaveBeenCalledWith('error', 'badOrigin');
            });
        });

        describe("when Current-User id has not changed", function () {
            it("replies to RP iframe with 'unchanged'", function () {
                // OP frame setup
                document = {cookie: 'Current-User=%7B%22userId%22%3A%22theuserid%22%7D;'};
                sm = SessionManagement(document);

                // RP message setup
                var clientId = 'apps_manager_js';
                var origin = 'http://relyingparty.com/somepage.html';
                var hash = sm._calculate_session_state(clientId, origin, 'theuserid', 'somesalt');
                var postMessageSpy = jasmine.createSpy('postMessageSpy');
                // The properties of this message event are described here: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
                var messageEvent = {
                    data: 'apps_manager_js ' + hash,
                    origin: origin,
                    source: {postMessage: postMessageSpy}
                };
                var handler = sm.buildMessageHandler(origin, clientId);


                handler(messageEvent);

                expect(postMessageSpy).toHaveBeenCalledWith('unchanged', origin);
            });
        });

        describe("when Current-User id has changed", function () {
            it("replies to RP iframe with 'changed'", function () {
                // OP frame setup
                document = {cookie: ''};
                sm = SessionManagement(document);

                // RP message setup
                var clientId = 'apps_manager_js';
                var origin = 'http://relyingparty.com/somepage.html';
                var hash = sm._calculate_session_state(clientId, origin, 'theuserid', 'somesalt');
                var postMessageSpy = jasmine.createSpy('postMessageSpy');
                // The properties of this message event are described here: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
                var messageEvent = {
                    data: 'apps_manager_js ' + hash,
                    origin: origin,
                    source: {postMessage: postMessageSpy}
                };
                var handler = sm.buildMessageHandler(origin, clientId);

                handler(messageEvent);

                expect(postMessageSpy).toHaveBeenCalledWith('changed', origin);
            });
        });

        describe("when the RP sends an invalid message format", function () {
            var clientId;
            var origin;
            var hash;
            var postMessageSpy;
            var handler;

            beforeEach(function () {
                // RP message setup
                clientId = 'apps_manager_js';
                origin = 'http://relyingparty.com/somepage.html';
                postMessageSpy = jasmine.createSpy('postMessageSpy');
                handler = sm.buildMessageHandler(origin, clientId);
            });

            it("replies to the RP iframe with 'error'", function () {
                handler({
                    data: hash,
                    origin: origin,
                    source: {postMessage: postMessageSpy}
                });
                expect(postMessageSpy).toHaveBeenCalledWith('error', origin);
            });

            it("replies to the RP iframe with 'error'", function () {
                handler({
                    data: 'clientwithnosessionstate asfd',
                    origin: origin,
                    source: {postMessage: postMessageSpy}
                });
                expect(postMessageSpy).toHaveBeenCalledWith('error', origin);
            });

            it("replies to the RP iframe with 'error'", function () {
                handler({
                    data: 'apps_manager_js hashwithoutsalt',
                    origin: origin,
                    source: {postMessage: postMessageSpy}
                });
                expect(postMessageSpy).toHaveBeenCalledWith('error', origin);
            });

            it("replies to the RP iframe with 'error'", function () {
                handler({
                    data: 'apps_manager_js .saltwithouthash',
                    origin: origin,
                    source: {postMessage: postMessageSpy}
                });
                expect(postMessageSpy).toHaveBeenCalledWith('error', origin);
            });
        });
    });
});