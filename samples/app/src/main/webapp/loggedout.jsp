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

<html>
<body>

	<h1>Sample Home Page</h1>

	<p>You are logged out of the sample app.</p>
	<ul>
		<c:if test="${not empty cflogout}">
			<li><a href="${cflogout}">Logout</a> of Cloud Foundry</li>
		</c:if>
		<li><a href="apps">Apps</a></li>
		<li><a href="<c:url value="/"/>">Home</a></li>
	</ul>
</body>
</html>
