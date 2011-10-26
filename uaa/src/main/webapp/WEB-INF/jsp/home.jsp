<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
  <title>Authorization Home</title>
  <link type="text/css" rel="stylesheet" href="<c:url value="/resources/style.css"/>"/>
</head>
<body>

  <h1>Authorization Service</h1>

  <div id="content">
    <h2>Home</h2>

    <p>This is test page to ensure that your account login is working.</p>

    <c:if test="${error}" >
      <div class="error">
		    <h2>Woops!</h2>
      	<p>${error}</p>
      </div>
    </c:if>

     <authz:authorize ifNotGranted="ROLE_USER">
      <h2>You are logged in but do not have the user role</h2>
      <div>You should never see this, but if you do, maybe you can <a href="<c:url value="/login"/>">log in here</a></div>
      <br/>
    </authz:authorize>

    <authz:authorize ifAllGranted="ROLE_USER">
      <h2>You are logged in</h2>
    </authz:authorize>

    <div style="text-align: center"><form action="<c:url value="/logout.do"/>"><input type="submit" value="Logout"/></form></div>

  </div>

  <div id="footer">Demo only</div>


</body>
</html>
