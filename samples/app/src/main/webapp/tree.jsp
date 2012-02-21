<%@ page session="false"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<html>
<head>
	<link type='text/css' rel='stylesheet' media='all' href="<c:url value="/resources/tree.css"/>" />
	<script type="text/javascript" src="<c:url value="/resources/js/jquery.min.js"/>"></script>
	<script type="text/javascript" src="<c:url value="/resources/js/jquery.simpletreeview.js"/>"></script>
	<script type="text/javascript">
	//<![CDATA[
	$(document).ready(function() {
		$("ul#tree").simpletreeview({collapsed:true});
	});
	//]]>
	</script>
</head>
<body>

<h1>${title}</h1>

Your ${name}:

    <ul id="tree" class="treeview">
      <c:forEach var="item" items="${items}">
        <li>${item.name}
        	<ul><c:forEach var="entry" items="${item}">
        		<li>${entry.key}: ${entry.value}</li>
		      </c:forEach>
        	</ul>
        </li>
      </c:forEach>
    </ul>

<p><a href="j_spring_security_logout">Logout</a></p>
</body>
</html>
