<%@ page import="org.springframework.security.web.WebAttributes" %>
<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Authorization Login</title>
<link type="text/css" rel="stylesheet"
	href="<c:url value="/resources/style.css"/>" />
<style type="text/css">
	.cf-hidden { display : none }
</style>
</head>

<body>

	<h1>Authorization</h1>

	<div id="content">

		<%
			if (session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) != null) {
		%>
		<div class="error">
			<h2>Woops!</h2>

			<p>
				Your login attempt was not successful. (<%=((Exception) session
						.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION))
						.getMessage()%>)
			</p>
		</div>
		<%
			}
		%>
		<c:remove scope="session" var="SPRING_SECURITY_LAST_EXCEPTION" />

		<authz:authorize ifNotGranted="ROLE_USER">
			<h2>Login</h2>

			<p>
				You need to authenticate.
			</p>
			<p>Enter your user name and password.</p>
			<form id="loginForm" name="loginForm"
				action="<c:url value="/login.do"/>" method="POST">
				<p>
					<label>Username: <input type='text' name='username'
						value="${username}" /> </label>
				</p>
				<p>
					<label>Password: <input type='password' name='password'
						value="" /> </label>
				</p>
				<p>
					<input name="login" value="Login" type="submit" />
				</p>
			</form>
		</authz:authorize>
	</div>

	<div id="footer">Demo only</div>


</body>
</html>
