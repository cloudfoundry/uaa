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
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.hamcrest.Description;
import org.junit.internal.matchers.TypeSafeMatcher;
import org.springframework.http.HttpStatus;

/**
 * @author Dave Syer
 * 
 */
public class ScimExceptionStatusCodeMatcher extends TypeSafeMatcher<ScimException> {

	private final HttpStatus status;

	public ScimExceptionStatusCodeMatcher(HttpStatus status) {
		this.status = status;
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("exception has status code ").appendValue(status);
	}

	@Override
	public boolean matchesSafely(ScimException e) {
		return e.getStatus() == status;
	}
}