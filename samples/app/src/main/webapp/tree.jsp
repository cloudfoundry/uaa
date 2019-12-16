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

	<ul>
		<li><a href="browse">Implicit Flow Demo</a></li>
		<li><a href="<c:url value="/"/>">Home</a></li>
	</ul>
</body>
</html>
