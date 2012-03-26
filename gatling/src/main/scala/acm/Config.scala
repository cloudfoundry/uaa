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
package acm


import com.excilys.ebi.gatling.http.Predef.httpConfig

/**
 * Basic configuration for the ACM.
 *
 * Edit `urlBase` or set GATLING_ACM_BASE env variable to run against a different URL
 */
object Config {
	val urlBase = sys.env.getOrElse("GATLING_ACM_BASE", "http://localhost:9090")

  val acm_user = "acm_user"
  val acm_password = "acm_password"

	def acmHttpConfig = httpConfig.baseURL(urlBase)

}
