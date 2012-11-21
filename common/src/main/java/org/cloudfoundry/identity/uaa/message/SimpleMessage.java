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

package org.cloudfoundry.identity.uaa.message;

import java.io.Serializable;

/**
 * Simple wrapper class for vanilla informational responses from REST endpoints.
 * 
 * @author Dave Syer
 *
 */
public class SimpleMessage implements Serializable {
	
	private String status;
	
	private String message;
	
	@SuppressWarnings("unused")
	private SimpleMessage() {
	}

	public SimpleMessage(String status, String message) {
		this.status = status;
		this.message = message;
	}

	public String getStatus() {
		return status;
	}

	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return "{\"status\"=\"" + status + "\",\"message\"=\"" + message + "\"}";
	}

	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return obj instanceof SimpleMessage && toString().equals(obj.toString());
	}
	
}
