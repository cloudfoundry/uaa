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

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<c:url var="baseUrl" value="/resources" />
<c:set value="www.cloudfoundry.com" var="hostName" />

<!DOCTYPE html>
<html>
<head>
<title>Cloud Foundry Login</title>
<link rel="stylesheet" href="${baseUrl}/stylesheets/openid.css" />
<script type="text/javascript" src="${baseUrl}/javascripts/jquery.js"></script>
<script type="text/javascript"
	src="${baseUrl}/javascripts/openid-jquery.js"></script>
<script type="text/javascript">
	$(document).ready(function() {
		openid.init('openid_identifier');
		//   openid.setDemoMode(true); Stops form submission for client javascript-only test purposes
	});
	(function() {
		// force ssl if cf.com
		var loc = window.location;
		if (loc.hostname.indexOf('cloudfoundry.com') >= 0
				&& loc.protocol == "http:") {
			window.location = "https://" + loc.host + loc.pathname + loc.search
					+ loc.hash;
		}
	})();
</script>
</head>
<body>
	<div>
		<div>
			<div>
				<div>
					<div>
						<div>

							<article class="container" style="position: relative;">
								<div style="float: left; width: 40%;">
									<form action="<c:url value="/j_spring_openid_security_check"/>"
										method="post" id="openid_form">
										<input type="hidden" name="action" value="verify" />

										<fieldset>
											<legend>Sign-in or Create New Account</legend>

											<div id="openid_choice">
												<p>Please click your account provider:</p>
												<div id="openid_btns"></div>

											</div>

											<div id="openid_input_area">
												<input id="openid_identifier" name="openid_identifier"
													type="text" value="http://" /> <input id="openid_submit"
													type="submit" value="Sign-In" />
											</div>
											<noscript>
												<p>
													OpenID is a service that allows you to log-on to many
													different websites using a single identity. Find out <a
														href="http://openid.net/what/">more about OpenID</a> and <a
														href="http://openid.net/get/">how to get an OpenID
														enabled account</a>.
												</p>
											</noscript>
										</fieldset>
									</form>

									<c:if test="${not empty param.error}">
										<div>
											<span class="flash">Login failed</span> <a
												href="http://${hostName}/passwd">Forgot password?</a>
										</div>
									</c:if>
									<c:if test="${error!=null}">
										<div class="error">
											<p>${error}</p>
										</div>
									</c:if>

									<c:if test="${not empty prompts}">
										<form id="loginForm" name="loginForm"
											action="<c:url value="/login.do"/>" method="POST" novalidate>
											<div>
												Alternatively, if you already registered and have a
												password, login with your existing Cloud Foundry account
												credentials:
												<c:forEach items="${prompts}" var="prompt">
													<label for="${prompt.key}">${prompt.value[1]}</label>
													<input id='${prompt.key}' type='${prompt.value[0]}'
														name='${prompt.key}' /> <br/>
												</c:forEach>
											</div>
											<div class="buttons">
												<button type="submit">Login</button>
												<span class="button-alt">or <a
													href="http://${hostName}/signup">sign up</a> for
													CloudFoundry.com
												</span>
											</div>
										</form>
									</c:if>
								</div>
							</article>

							<%-- Clear out session scoped attributes, don't leak info --%>
							<c:if
								test="${not empty sessionScope['SPRING_SECURITY_LAST_EXCEPTION']}">
								<c:set scope="session" var="SPRING_SECURITY_LAST_EXCEPTION"
									value="${null}" />
							</c:if>
							<c:if
								test="${not empty sessionScope['SPRING_SECURITY_LAST_USERNAME']}">
								<c:set scope="session" var="SPRING_SECURITY_LAST_USERNAME"
									value="${null}" />
							</c:if>

						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</body>
</html>
