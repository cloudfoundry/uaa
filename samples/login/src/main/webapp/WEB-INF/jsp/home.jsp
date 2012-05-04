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

<c:url var="baseUrl" value="/resources" />
<c:set value="www.cloudfoundry.com" var="hostName" />

<!DOCTYPE html>
<!--[if IE]>  <![endif]-->
<!--[if lt IE 7 ]> <html lang="en" dir="ltr" class="no-js old_ie ie6"> <![endif]-->
<!--[if IE 7 ]> <html lang="en" dir="ltr" class="no-js old_ie ie7"> <![endif]-->
<!--[if IE 8 ]> <html lang="en" dir="ltr" class="no-js ie8"> <![endif]-->
<!--[if IE 9 ]> <html lang="en" dir="ltr" class="no-js ie9"> <![endif]-->
<!--[if (gt IE 9)|!(IE)]> ><! <![endif]-->
<html class='no-js' dir='ltr' lang='en'>
<!-- <![endif] -->
<head>
<title>Cloud Foundry Login Home</title>
<meta charset='utf-8'>
<meta content='IE=edge,chrome=1' http-equiv='X-UA-Compatible'>
<meta content='VMware' name='author' />
<meta content='Copyright VMware 2011. All Rights Reserved.'
	name='copyright' />
<link href='${baseUrl}/favicon.ico' rel='shortcut icon' />
<meta content='all' name='robots' />
<link href='${baseUrl}/stylesheets/print.css' media='print'
	rel='stylesheet' type='text/css' />
<link href='${baseUrl}/stylesheets/master.css' media='screen'
	rel='stylesheet' type='text/css' />
<!--[if lt IE 9 ]> <link href="${baseUrl}/stylesheets/ie.css" media="screen" rel="stylesheet" type="text/css" /> <![endif]-->
<!--[if lt IE 8 ]> <link href="${baseUrl}/stylesheets/ie7.css" media="screen" rel="stylesheet" type="text/css" /> <![endif]-->
<link href='${baseUrl}/stylesheets/master-cf.css' media='screen'
	rel='stylesheet' type='text/css' />
<style media='screen' type='text/css'>
.js-hide {
	display: none;
}

.js-show {
	display: block;
}

.fouc-fix {
	display: none;
}
</style>
<meta content='' name='Description' />
<meta content='' name='keywords' />
<style type='text/css'>
img.gsc-branding-img,img.gsc-branding-img-noclear,img.gcsc-branding-img,img.gcsc-branding-img-noclear
	{
	display: none;
}

.gs-result .gs-title,.gs-result .gs-title * {
	color: #0094d4;
}
</style>
<script type="text/javascript" src="${baseUrl}/javascripts/jquery.js"></script>
</head>
<body id="micro">
	<div class='wrapper'>
		<div class='container' id='header'>
			<div class='site-wrap'>
				<div class='container'>
					<div class='span-6 logo-wrap'>
						<a href='http://${hostName}/'> <img
							alt="Cloud Foundry: The Industry's Open Platform As A Service"
							src='${baseUrl}/images/logo_header_cloudfoundry.png' width='373'
							height='70'> <span class='replaced'>Cloud Foundry:
								The Industry's Open Platform As A Service</span> </img>
						</a>
					</div>
					<div class='span-9 last'>
						<div class='right'>
							<form action='http://${hostName}/search' class='search-form'
								method='get'>
								<input autocomplete='off' class='search-input' name='q'
									placeholder='search' type='text' value='' />
							</form>
							<ul class='super-nav'>
								<li><span>Welcome <strong>${fn:escapeXml(pageContext.request.userPrincipal.name)}</strong></span>
									/ <c:url value="/logout.do" var="url" /> <a
									href="${fn:escapeXml(url)}">Logout</a> &nbsp;</li>
							</ul>
						</div>
						<div id='nav'>
							<ul>
								<li><a href='http://start.cloudfoundry.com/'>Get
										Started</a></li>
								<li><a href='http://${hostName}/getinvolved'>Get
										Involved</a></li>
								<li><a href='http://${hostName}/partners'>Partners</a></li>
								<li><a href='http://blog.cloudfoundry.com'>Blog</a></li>
								<li><a href='http://${hostName}/about'>About</a></li>
							</ul>
						</div>
					</div>
				</div>
			</div>
		</div>
		<div class='container' id='main'>
			<div class='content-wrap'>
				<div class='site-wrap'>
					<div class='container content'>
						<div class='span-15 prepend-top'>
							<h2>Home</h2>

							<p>This is test page to ensure that your account login is
								working.</p>

							<c:if test="${error}">
								<div class="error">
									<h2>Woops!</h2>
									<p>${error}</p>
								</div>
							</c:if>

							<h2>You are logged in</h2>

						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
	<div class='container' id='footer'>
		<div class='site-wrap'>
			<div class='row'>
				<div class='span-3 social-icons'>
					<a class='twitter replaced'
						href='http://twitter.com/#!cloudfoundry' rel='external'
						target='_blank'>Twitter</a> <a class='facebook replaced'
						href='http://facebook.com/cloudfoundry' rel='external'
						target='_blank'>Facebook</a> <a class='youtube replaced'
						href='http://www.youtube.com/cloudfoundry' rel='external'
						target='_blank'>YouTube</a>
				</div>
				<div class='prepend-2 span-5'>
					<p>
						<a href='http://${hostName}/faq'>FAQ</a> | <a
							href='http://support.cloudfoundry.com' target='_blank'>Forums</a>
						| <a href='http://blog.cloudfoundry.com'>Blog</a> | <a
							href='http://${hostName}/jobs'>Jobs</a> | <a
							href='http://${hostName}/legal'>Legal</a> | <a
							href='http://www.vmware.com/help/privacy.html' target='_blank'>Privacy</a>
					</p>
				</div>
				<div class='span-5 last right'>
					<p>
						Copyright &copy;
						<fmt:formatDate value="<%= new java.util.Date() %>" pattern="yyyy" />
						VMware, Inc. All rights reserved.
					</p>
				</div>
			</div>
		</div>
	</div>
	<script>
		var _gaq = _gaq || [];
		_gaq.push([ '_setAccount', 'UA-22181585-1' ]);
		_gaq.push([ '_trackPageview' ]);
		(function() {
			var ga = document.createElement('script');
			ga.type = 'text/javascript';
			ga.async = true;
			ga.src = ('https:' == document.location.protocol ? 'https://ssl'
					: 'http://www')
					+ '.google-analytics.com/ga.js';
			var s = document.getElementsByTagName('script')[0];
			s.parentNode.insertBefore(ga, s);
		})();
	</script>
	<script type="text/javascript"
		src="//www.vmware.com/files/templates/inc/s_code_vmw.js"></script>
</body>
</html>
