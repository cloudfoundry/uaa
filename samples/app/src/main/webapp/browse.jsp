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
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ page session="false"%>
<html>
<head>
<title>Client Authentication Example</title>
	<script type="text/javascript" src="resources/js/libs/json2.js"></script>
	<script type="text/javascript" src="resources/js/libs/localstorage.js"></script>
	<script type="text/javascript" src="resources/js/libs/modernizr-2.5.3.min.js"></script>
	<script type="text/javascript" src="resources/js/jquery.min.js"></script>
	<script type="text/javascript" src="resources/js/libs/jso.js"></script>
	<script type="text/javascript">
	$(document).ready(function() {

		// Add configuration for one or more providers.
		jso_configure({
			"uaa": {
				client_id: "${clientId}",
				redirect_uri: window.location,
				authorization: "${userAuthorizationUri}",
			}
		});

		// Perform a data request
		$.oajax({
			url: "${dataUri}",
			jso_provider: "uaa",
			jso_allowia: true,
			jso_scopes: ["openid", "cloud_controller.read"],
			dataType: 'json',
			success: function(data) {
				console.log({response:data});
				$('#message').html(JSON.stringify(data));
			},
			error: function(xhr, text) {
				console.log("There was an error: " + text);
			}
		});

		jso_dump();
		jso_wipe();

	});
</script>
</head>
<body>
	<h1>Client Authentication Sample</h1>

	<div id="content">
		<p>Some JavaScript in this page will log you in as client "${clientId}" acting on
			behalf of a user. Once you have authenticated as a user and approved the
			access, it will render JSON representation of your apps from the API Resource Server below:</p>
		<p id="message" />
	</div>
<ul>
<li><a href="apps">Apps</a></li>
<li><a href="j_spring_security_logout">Logout</a></li>
<li><a href="<c:url value="/"/>">Home</a></li>
</ul>
</body>
</html>
