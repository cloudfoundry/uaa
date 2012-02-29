<%--

    Cloud Foundry 2012.02.03 Beta
    Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.

    This product is licensed to you under the Apache License, Version 2.0 (the "License").
    You may not use this product except in compliance with the License.

    This product includes a number of subcomponents with
    separate copyright notices and license terms. Your use of these
    subcomponents is subject to the terms and conditions of the
    subcomponent's license, as noted in the LICENSE file.

--%>
<%@ page session="false"%>

<html>
<head>
<title>Client Authentication Example</title>
<script type="text/javascript"
	src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
<script>
	function authenticate() {
		var appID = "my";
		console.log("App ID: " + appID)
		console.log("Location: " + window.location)
		var path = '${userAuthorizationUri}?';
		var queryParams = [ 'client_id=' + appID,
				'redirect_uri=' + window.location, 'scope=read',
				'response_type=token' ];
		var query = queryParams.join('&');
		var url = path + query;
		console.log("url: " + url)
		window.open(url);
	}
	function display() {
		var hash = window.location.hash;
		console.log('hash: ' + hash);
		var accessToken = hash.split('&')[0].split("=")[1];
		console.log('access-token:' + accessToken);
		var headers = {
			'Authorization' : 'Bearer ' + accessToken,
			'Accept' : 'application/json'
		};
		$.ajaxSetup({
			'headers' : headers,
			dataType : 'text'
		});
		$.get('${dataUri}', function(data) {
			console.log('data:' + data);
			$('#message').html(data);
		});
	}
	$(function() {
		if (window.location.hash.length == 0) {
			authenticate();
		} else {
			display();
		}
	})
</script>
</head>
<body>
	<h1>Client Authentication Sample</h1>

	<div id="content">
		<p>Some JavaScript in this page will log you in as client app "my" acting on
			behalf of a user. Once you have authenticated as a user and approved the
			access, it will render a message from the API Resource Server below:</p>
		<p id="message" />
	</div>
</body>
</html>
