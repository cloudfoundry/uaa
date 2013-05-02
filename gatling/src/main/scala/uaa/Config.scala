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
import java.io.File
import io.Source
import com.excilys.ebi.gatling.http.config.HttpProtocolConfiguration

/**
 */
object Config {
  // Number of base data users to create
  val nUsers = 1000

  // Number of base data groups to create
  val nGroups = 50

  // Average number of members in a group
  val avgGroupSize = nUsers/nGroups

  def yetiTarget = for {
    userHome <- sys.props.get("user.home")
    yetiFile  = new File(userHome + "/.bvt/config.yml")
    if (yetiFile.exists())
    content = Source.fromFile(yetiFile).getLines().toSeq
    if (content.length > 1)
    target <- "target: (.*)".r.findPrefixMatchOf(content(1)).map(_.group(1).trim)
  } yield {
    target
  }

  def baseUrl = (sys.env.get("VCAP_BVT_TARGET") orElse yetiTarget) map (_.replace("ccng.", ""))

  private def prependHttp(url: String) = if (url.startsWith("http")) url else "http://" + url


  // The bootstrap admin user
  val admin_client_id = sys.env.getOrElse("VCAP_BVT_ADMIN_CLIENT", "admin")
  val admin_client_secret = sys.env.getOrElse("VCAP_BVT_ADMIN_SECRET", "adminsecret")

  // "Varz" client
  val varz_client_id = sys.env.getOrElse("GATLING_UAA_VARZ_CLIENT", "varz")
  val varz_client_secret = sys.env.getOrElse("GATLING_UAA_VARZ_SECRET", "varzclientsecret")

  // Client to mimic a registered application for authorization code flows etc.
  val appClient = Client(
      id = "gatling_app",
      secret= "app_client_secret",
      scopes = Seq("cloud_controller.read","cloud_controller.write","openid","password.write","tokens.read","tokens.write"),
      redirectUri = Some("http://localhost:8080/app"),
      resources = Seq("uaa.none"),
      authorities = Seq("cloud_controller.read","cloud_controller.write","openid","password.write","tokens.read","tokens.write"),
      grants = Seq("client_credentials", "authorization_code", "refresh_token"))

  // Scim client which is registered by the admin user in order to create users
  val scimClient = Client("scim_client", "scim_client_secret",
    Seq("uaa.none"), Seq("uaa.none"), Seq("scim.read","scim.write","password.write"))

  // The base user data
  val users: Seq[User] = (1 to nUsers).map(i => User("shaun" + i, "password"))

  // The base group data
  val groups: Seq[Group] = (1 to nGroups).map(i => Group("acme." + i, Seq(User("shaun" + i, "password"))))

  def uaaHttpConfig = {
    val uaaUrl = baseUrl map (prependHttp) map (_.replace("://", "://uaa.")) getOrElse "http://localhost:8080/uaa"
    println("**** Targeting UAA at: " + uaaUrl)
    httpConfig.baseURL(uaaUrl).disableFollowRedirect.disableAutomaticReferer.warmUp(uaaUrl)
  }

  def loginHttpConfig = {
    val loginUrl = baseUrl map (prependHttp) map (_.replace("://", "://login.")) getOrElse "http://localhost:8080/uaa"
    println("**** Targeting Login server at: " + loginUrl)
    httpConfig.baseURL(loginUrl).disableFollowRedirect.disableAutomaticReferer.warmUp(loginUrl)
  }

}
