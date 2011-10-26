<%@ page
	import="org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<html>
<body>

<h1>OpenID Sample Error Page</h1>

<p>
There was a problem logging you in.  Don't panic.
</p>
<ul>
<li><a href="apps">Apps</a></li>
<li><a href="services">Services</a></li>
<li><a href="<c:url value="/"/>">Home</a></li>
</ul>
		<%
			if (session.getAttribute(AbstractAuthenticationProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY) != null) {
		%>
		<div class="error">
			<p>
				<%= session
						.getAttribute(AbstractAuthenticationProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY) %>
				<% ((Exception) session
						.getAttribute(AbstractAuthenticationProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY)).printStackTrace();%>
			</p>
		</div>
		<%
			}
		%>
</body>
</html>
