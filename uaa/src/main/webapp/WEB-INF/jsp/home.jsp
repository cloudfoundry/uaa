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
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<title>Success | Cloud Foundry</title>
</head>
<body id="micro">
	<div class="content">
		<div>
			<div>
				<h2>Success</h2>

				<p>Your account login is working and you have authenticated.</p>

				<c:if test="${error!=null}">
					<div class="error" title="${error}">
						<p>But there was an error.</p>
					</div>
				</c:if>

				<h2>You are logged in.</h2>

				<p>
					<c:url value="/logout.do" var="url" />
					<a href="${fn:escapeXml(url)}">Logout</a> &nbsp;
				</p>

			</div>
		</div>
		<div title="Version: ${app.version}, Commit: ${commit_id}, Timestamp: ${timestamp}">
			Copyright &copy;
			<fmt:formatDate value="<%=new java.util.Date()%>" pattern="yyyy" />
			Pivotal Software, Inc. All rights reserved.
		</div>
	</div>
</body>
</html>
