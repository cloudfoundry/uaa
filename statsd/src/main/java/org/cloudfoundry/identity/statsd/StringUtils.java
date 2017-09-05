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

package org.cloudfoundry.identity.statsd;

/**
 * @author Dave Syer
 *
 */
public class StringUtils {

	/**
	 * Convert a string from camel case to underscores, also replacing periods with underscores (so for example a fully
	 * qualified Java class name gets underscores everywhere).
	 * 
	 * @param value a camel case String
	 * @return the same value with camels converted to underscores
	 */
	public static String camelToUnderscore(String value) {
		String result = value.replace(" ", "_");
		result = result.replaceAll("([a-z])([A-Z])", "$1_$2");
		result = result.replace(".", "_");
		result = result.toLowerCase();
		return result;
	}
}
