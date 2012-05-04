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
<c:url var="faviconUrl" value="/favicon.ico" />
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
<title>Cloud Foundry Login</title>
<meta charset='utf-8'>
<meta content='IE=edge,chrome=1' http-equiv='X-UA-Compatible'>
<meta content='VMware' name='author' />
<meta content='Copyright VMware 2011. All Rights Reserved.'
	name='copyright' />
<link href='${faviconUrl}' rel='shortcut icon' />
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
<link href='${baseUrl}/stylesheets/micro.css' media='screen'
	rel='stylesheet' type='text/css' />
<link rel="stylesheet" href="${baseUrl}/stylesheets/openid.css"
	type="text/css" />
<script type="text/javascript" src="${baseUrl}/javascripts/jquery.js"></script>
<script type="text/javascript"
	src="${baseUrl}/javascripts/openid-jquery.js"></script>
<script type="text/javascript">
	$(document).ready(function() {
		openid.init('openid_identifier');
		//   openid.setDemoMode(true); Stops form submission for client javascript-only test purposes
	});
	(function() {
		// force ssl if cf.com
		var loc = window.location;
		if (loc.hostname.indexOf('cloudfoundry.com') >= 0
				&& loc.protocol == "http:") {
			window.location = "https://" + loc.host + loc.pathname + loc.search
					+ loc.hash;
		}
	})();
</script>
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

							<article class="container" style="position: relative;">
								<div style="float: left; width: 40%;">
									<form action="<c:url value="/j_spring_openid_security_check"/>"
										method="post" id="openid_form">
										<input type="hidden" name="action" value="verify" />

										<fieldset>
											<legend>Sign-in or Create New Account</legend>

											<div id="openid_choice">
												<p>Please click your account provider:</p>
												<div id="openid_btns"></div>

											</div>

											<div id="openid_input_area">
												<input id="openid_identifier" name="openid_identifier"
													type="text" value="http://" /> <input id="openid_submit"
													type="submit" value="Sign-In" />
											</div>
											<noscript>
												<p>
													OpenID is a service that allows you to log-on to many
													different websites using a single identity. Find out <a
														href="http://openid.net/what/">more about OpenID</a> and <a
														href="http://openid.net/get/">how to get an OpenID
														enabled account</a>.
												</p>
											</noscript>
										</fieldset>
									</form>

									<form id="loginForm" name="loginForm"
										action="<c:url value="/login.do"/>" method="POST" novalidate>
										<div>
											Alternatively, if you already registered and have a password,
											login with your existing Cloud Foundry account credentials:
											<c:if test="${not empty param.error}">
												<div>
													<span class="flash">Login failed</span> <a
														href="http://${hostName}/passwd">Forgot password?</a>
												</div>
											</c:if>
											<c:forEach items="${prompts}" var="prompt">
												<label for="${prompt.key}">${prompt.value[1]}</label>
												<input id='${prompt.key}' type='${prompt.value[0]}'
													name='${prompt.key}' />
											</c:forEach>
										</div>
										<div class="buttons">
											<button type="submit">Login</button>
											<span class="button-alt">or <a
												href="http://${hostName}/signup">sign up</a> for
												CloudFoundry.com
											</span>
										</div>
									</form>

									<hr />
									<section class="learnmore">
										<h2>Learn more</h2>
										<ul>
											<li><a href="http://www.youtube.com/cloudfoundry">Watch
													the Screencast</a></li>
											<li><a
												href="http://support.cloudfoundry.com/entries/20316811-micro-cloud-foundry-installation-setup">Read
													the Getting Started Guide</a></li>
											<li><a
												href="http://support.cloudfoundry.com/forums/20180298-micro-cloud-foundry-documents">Find
													Answers in the Knowledge Base</a></li>
										</ul>
									</section>
								</div>
							</article>

							<%-- Clear out session scoped attributes, don't leak info --%>
							<c:if
								test="${not empty sessionScope['SPRING_SECURITY_LAST_EXCEPTION']}">
								<c:set scope="session" var="SPRING_SECURITY_LAST_EXCEPTION"
									value="${null}" />
							</c:if>
							<c:if
								test="${not empty sessionScope['SPRING_SECURITY_LAST_USERNAME']}">
								<c:set scope="session" var="SPRING_SECURITY_LAST_USERNAME"
									value="${null}" />
							</c:if>

							<!--
								Start of DoubleClick Floodlight Tag: Please do not remove
								Activity name of this tag: Micro Cloud Foundry - Landing Page Arrival
								URL of the webpage where the tag is expected to be placed: https://www.cloudfoundry.com/micro
								This tag must be placed between the <body> and </body> tags, as close as possible to the opening tag.
								Creation Date: 08/18/2011
								-->
							<script type="text/javascript">
								var axel = Math.random() + "";
								var a = axel * 10000000000000;
								document
										.write('<iframe src="https://fls.doubleclick.net/activityi;src=2645750;type=cloud806;cat=micro467;ord='
												+ a
												+ '?" width="1" height="1" frameborder="0" style="display:none"></iframe>');
							</script>
							<noscript>
								<iframe
									src="https://fls.doubleclick.net/activityi;src=2645750;type=cloud806;cat=micro467;ord=1?"
									width="1" height="1" frameborder="0" style="display: none"></iframe>
							</noscript>
							<!-- End of DoubleClick Floodlight Tag: Please do not remove -->

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
				<div class='span-5 last right'
					title="Commit: ${commit_id}, Timestamp: ${timestamp}">
					<p>
						Copyright &copy;
						<fmt:formatDate value="<%=new java.util.Date()%>" pattern="yyyy" />
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
