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
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<!DOCTYPE html>
<html>
<head>
<title>Cloud Foundry Login User Approval</title>
</head>
<body>
	<div>
		<div>
			<div>
				<div>
					<div>
						<div>
							<c:if test="${error!=null}">
								<div class="error">
									<h2>Woops!</h2>
									<p>${error}</p>
								</div>
							</c:if>

							<h2>Please Confirm</h2>

							<p>Do you authorize ${auth_request.clientId} to access your
								protected resources in scope ${auth_request.scope}?</p>

							<form id="confirmationForm" name="confirmationForm" method="POST">
								<input name="${options.confirm.key}" value="${options.confirm.value}" type="hidden" />
								<div class="buttons">
									<button type="submit">Authorize</button>
								</div>
							</form>
							<form id="denialForm" name="denialForm" method="POST">
								<input name="${options.deny.key}" value="${options.deny.value}" type="hidden" />
								<div class="buttons">
									<button type="submit">Deny</button>
								</div>
							</form>

						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</body>
</html>
