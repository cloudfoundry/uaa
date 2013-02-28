/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.api.web;

import static org.junit.Assert.*;

import java.util.HashMap;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.servlet.View;

/**
 * @author Dave Syer
 *
 */
public class ApiControllerTests {
	
	private ApiController controller = new ApiController();

	@Test
	public void testNoUser() throws Exception {
		controller.setInfo(new ClassPathResource("info.tmpl"));
		HashMap<String, Object> model = new HashMap<String, Object>();
		View view = controller.info(model, null);
		MockHttpServletResponse response = new MockHttpServletResponse();
		view.render(model, new MockHttpServletRequest(), response);
		String content = response.getContentAsString();
		assertFalse("Wrong content: "+content, content.contains("\"user\""));
	}

	@Test
	public void testWithUser() throws Exception {
		controller.setInfo(new ClassPathResource("info.tmpl"));
		HashMap<String, Object> model = new HashMap<String, Object>();
		View view = controller.info(model, new UsernamePasswordAuthenticationToken("marissa", "<NONE>"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		view.render(model, new MockHttpServletRequest(), response);
		String content = response.getContentAsString();
		assertTrue("Wrong content: "+content, content.contains("\n  \"user\": \"marissa\""));
	}

}
