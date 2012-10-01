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
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>

<!DOCTYPE html>
<html>
<head>
<title>Cloud Foundry Login Home</title>
</head>
<body>
	<div>
		<div>
			<div>
				<div>
					<div>
						<div>
							<h2>Home</h2>

							<p>Your account login is working and you are authenticated.</p>

							<c:if test="${error!=null}">
								<div class="error">
									<h2>Woops!</h2>
									<p>${error}</p>
								</div>
							</c:if>

							<p>
								<c:url value="/logout.do" var="url" />
								<a href="${fn:escapeXml(url)}">Logout</a> &nbsp;
							</p>

						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</body>
</html>
