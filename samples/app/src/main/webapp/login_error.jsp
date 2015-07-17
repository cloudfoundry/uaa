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
<%@ page import="org.springframework.security.web.WebAttributes" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<html>
<body>

<h1>Sample Error Page</h1>

<p>
There was a problem logging you in.  Don't panic.
</p>
<ul>
<li><a href="apps">Apps</a></li>
<li><a href="services">Services</a></li>
<li><a href="j_spring_security_logout">Logout</a></li>
<li><a href="<c:url value="/"/>">Home</a></li>
</ul>
		<%
			if (session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) != null) {
		%>
		<div class="error">
			<p>
				<%= session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) %>
				<% ((Exception) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)).printStackTrace();%>
			</p>
		</div>
		<%
			}
		%>
</body>
</html>
