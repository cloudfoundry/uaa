/**
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

import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.core.structure.ChainBuilder

import uaa.OAuthComponents._
import java.util.concurrent.TimeUnit

/**
 */
object ScimComponents {

  /**
   * Creates 'n' users by invoking the SCIM API.
   *
   * Usernames can optionally be prefixed
   */
  def createScimUsers(n: Int, usernamePrefix: String = "joe"): ChainBuilder = {
    clientCredentialsAccessTokenRequest(
      username = "scim",
      password = "scimsecret",
      client_id = "scim",
      scope = "write password").insertChain(
        chain.loop(
          chain.feed(UsernamePasswordFeeder(usernamePrefix))
            .insertChain(createScimUserChain)
            .pause(50, 100, TimeUnit.MILLISECONDS)).times(n))
  }

  /**
   * Creates a SCIM user.
   *
   * A suitable access token must already be available in the session, as well as username and password values.
   *
   */
  private val createScimUserChain: ChainBuilder = {
    chain.exec(
      http("Create User")
        .post("/User")
        .header("Authorization", "Bearer ${access_token}")
        .body("""{"name":{"givenName":"Joe","familyName":"User","formatted":"Joe User"},"userName":"${username}","emails":[{"value":"${username}@blah.com"}]}""")
        .asJSON()
        .check(status.is(201), regex(""""id":"(.*?)"""").saveAs("__scimUserId")))
      .exec(
        http("Change Password")
          .put("/User/${__scimUserId}/password")
          .header("Authorization", "Bearer ${access_token}")
          .body("""{"password":"${password}"}""")
          .asJSON()
          .check(status.is(204))).exec((s: Session) => {
          s.removeAttribute("__scimUserId")
        })

  }

}
