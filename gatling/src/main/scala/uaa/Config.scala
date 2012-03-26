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
package uaa

import com.excilys.ebi.gatling.http.Predef.httpConfig

/**
 */
object Config {
	val urlBase = sys.env.getOrElse("GATLING_UAA_BASE", "http://localhost:8080/uaa")

  val uaa_admin_user = "admin"
  val uaa_admin_password = "admin"

  val scim_client_id = "scim"
  val scim_client_password = "scimsecret"

	def uaaHttpConfig = httpConfig.baseURL(urlBase)

}
