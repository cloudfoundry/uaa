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
<title>Access Confirmation | Cloud Foundry</title>
</head>
<body id="micro">
	<div class="content">
		<div>
			<c:if test="${error!=null}">
				<div class="error" title="${fn:escapeXml(error)}">
					<h2>Sorry</h2>
					<p>There was an error. The request for authorization was invalid.</p>
				</div>
			</c:if>
			<c:if test="${error==null}">

				<h2>Please Confirm</h2>
                <form id="confirmationForm" name="confirmationForm"
                    action="${options.confirm.path}" method="POST">

					<div class="confirm">
						<p>
							Do you authorize the application '${client_id}' at <a
								href="${redirect_uri}">${redirect_uri}</a> to access your Cloud
							Foundry resources?
						</p>
						<c:set var="count" value="0" />
						<c:if test="${(approved_scopes != null) && (! empty approved_scopes)}">
							<p> You have already approved '${client_id}' with access to the following: </p>
							<c:forEach items="${approved_scopes}" var="scope">
								<input type="checkbox" checked="checked" name="scope.${count}" value="${scope['code']}"><spring:message code="${scope['code']}"
							       		text="${scope['text']}" /><br/>
							    <c:set var="count" value="${count + 1}" />
							</c:forEach>
						</c:if>
						<c:if test="${(denied_scopes != null) && (! empty denied_scopes)}">
							<p> You have already denied '${client_id}' access to the following: </p>
							<c:forEach items="${denied_scopes}" var="scope">
	                           <input type="checkbox" checked="checked" name="scope.${count}" value="${scope['code']}"><spring:message code="${scope['code']}"
	                                   text="${scope['text']}" /><br/>
	                           <c:set var="count" value="${count + 1}" />
	                       </c:forEach>
	                    </c:if>
	                    <c:if test="${(undecided_scopes != null) && (! empty undecided_scopes)}">
	                       <p> Do you want to allow '${client_id}' to: </p>
	                       <c:forEach items="${undecided_scopes}" var="scope">
	                           <input type="checkbox" checked="checked" name="scope.${count}" value="${scope['code']}"><spring:message code="${scope['code']}"
	                                   text="${scope['text']}" /><br/>
                               <c:set var="count" value="${count + 1}" />
	                       </c:forEach>
	                    </c:if>
	                    
	                    <c:if test="${(approved_scopes != null) && (! empty approved_scopes) || (denied_scopes != null) && (! empty denied_scopes)}">
	                       <p>Do you wish to change these selections?</p>
	                    </c:if>
						<p>If you do not recognize the application or the URL in the
							link above you should deny access by unchecking all these boxes.</p>
					</div>

					<input name="${options.confirm.key}"
						value="${options.confirm.value}" type="hidden" />
					<div class="buttons">
						<button class="button" type="submit">Ok</button>
					</div>
				</form>
				<form id="denialForm" name="denialForm"
					action="${options.deny.path}" method="POST">
					<input name="${options.deny.key}" value="${options.deny.value}"
						type="hidden" />
					<div class="buttons">
						<button class="button" type="submit">Cancel</button>
					</div>
				</form>

			</c:if>

		</div>
	</div>
	<div class="footer"
        title="Version: ${app.version}, Commit: ${commit_id}, Timestamp: ${timestamp}">
        Copyright &copy;
        <fmt:formatDate value="<%=new java.util.Date()%>" pattern="yyyy" />
        Pivotal Software, Inc. All rights reserved.
    </div>
	
</body>
</html>
