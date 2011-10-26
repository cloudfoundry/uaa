<%@ page
	import="org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter"%>
<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>OpenID Authorization</title>
<link type="text/css" rel="stylesheet"
	href="<c:url value="/resources/style.css"/>" />
</head>

<body>

	<h1>OpenID Attribute Authorization</h1>

	<div id="content">

		<p>
			The site
			<pre>${openid.site}</pre>
			is asking to retrieve your email and fullname from the OpenID
			provider:
		<pre>${openid.identity}</pre>
		</p>

		<form id="loginForm" name="loginForm"
			action="<c:url value="/openid/authorize"/>" method="POST">
			<p>
				<input name="approve" value="Approve" type="submit" /> <input
					name="deny" value="Deny" type="submit" />
			</p>
		</form>
	</div>

	<div id="footer">Demo only</div>


</body>
</html>
