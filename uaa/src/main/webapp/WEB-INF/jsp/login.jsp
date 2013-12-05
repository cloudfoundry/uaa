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

<!DOCTYPE html>
<html lang='en'>
<head>
<title>UAA Login | Cloud Foundry</title>
<meta charset='utf-8'>
</head>
<body id="micro">
	<div class="content">
		<article class="container">
			<p>Sign in with your CloudFoundry credentials.</p>
			<form id="loginForm" name="loginForm"
				action="<c:url value="/login.do"/>" method="POST" novalidate>
				<div>
					<c:if test="${not empty param.error}">
						<div class="flash">Sorry, we couldn't verify your email and
							password.</div>
					</c:if>
					<c:forEach items="${prompts}" var="prompt">
						<input id='${prompt.key==null ? prompt.name : prompt.key}' type='${prompt.key==null ? prompt.type : prompt.value[0]}'
							name='${prompt.key==null ? prompt.name : prompt.key}' placeholder='${prompt.key==null ? prompt.text : prompt.value[1]}' />
					</c:forEach>
				</div>
				<button type="submit" class="button">Sign in</button>
			</form>
		</article>
		<div class="message">
			<p>
				If you are reading this you are probably in the wrong place because
				the UAA does not support a branded UI out of the box. To login to
				<code>Pivotal Web Services</code>
				<a href="https://login.run.pivotal.io">click here.</a> If you were
				re-directed here by another application, please contact the owner of
				that application and tell them to use the Login Server as UI entry
				point.
			</p>
		</div>
	</div>
	<div class="footer"
		title="Version: ${app.version}, Commit: ${commit_id}, Timestamp: ${timestamp}">
		Copyright &copy;
		<fmt:formatDate value="<%=new java.util.Date()%>" pattern="yyyy" />
		Pivotal Software, Inc. All rights reserved.
	</div>
</body>
</html>
