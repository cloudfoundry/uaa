<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Sparklr</title>
<link type="text/css" rel="stylesheet"
	href="<c:url value="/resources/style.css"/>" />
</head>

<body>

	<h1>Authorization</h1>

	<div id="content">

		<c:if test="${error}">
			<div class="error">
				<h2>Woops!</h2>
				<p>${error}</p>
			</div>
		</c:if>

		<authz:authorize ifAllGranted="ROLE_USER">
			<h2>Please Confirm</h2>

			<p>Do you authorize ${client.clientId} to access your protected
				resources in scope ${auth_request.scope}.</p>

			<form id="confirmationForm" name="confirmationForm"
				action="${options.confirm.location}" method="POST">
				<input name="${options.confirm.key}"
					value="${options.confirm.value}" type="hidden" /> <label><input
					name="authorize" value="Authorize" type="submit">
				</label>
			</form>
			<form id="denialForm" name="denialForm"
				action="${options.deny.location}" method="POST">
				<input name="${options.deny.key}" value="${options.deny.value}"
					type="hidden" /> <label><input name="deny" value="Deny"
					type="submit">
				</label>
			</form>
		</authz:authorize>
	</div>

	<div id="footer">Demo only</div>


</body>
</html>
