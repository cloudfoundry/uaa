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

import java.util.regex.Pattern

import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.core.check.ExtractorFactory
import com.excilys.ebi.gatling.core.check.MatcherCheckBuilder
import com.excilys.ebi.gatling.core.structure.ChainBuilder
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.http.check.HttpCheck
import com.excilys.ebi.gatling.http.check.HttpExtractorCheckBuilder
import com.excilys.ebi.gatling.http.request.HttpPhase
import com.ning.http.client.Response

import AccessTokenCheckBuilder._

/**
 * Checks for the presence of an access token in the fragment of the Location header or JSON body
 */
object AccessTokenCheckBuilder {
  val fragmentTokenPattern = Pattern.compile(".*#.*access_token=([^&]+).*")
  val jsonBodyTokenPattern = Pattern.compile(""""access_token":"(.*?)"""")

  def fragmentToken = new FragmentTokenCheckBuilder

  def jsonToken = new JsonTokenCheckBuilder

  private[uaa] def fragmentExtractorFactory: ExtractorFactory[Response, String] = { (response: Response) =>
    (expression: String) =>
      val matcher = fragmentTokenPattern.matcher(response.getHeader("Location"))

      if (matcher.find()) Some(matcher.group(1)) else None
  }

  private[uaa] def jsonExtractorFactory: ExtractorFactory[Response, String] = { (response: Response) =>
    (expression: String) =>
      val matcher = jsonBodyTokenPattern.matcher(response.getResponseBody)

      if (matcher.find()) Some(matcher.group(1)) else None
  }

}

private[uaa] class FragmentTokenCheckBuilder extends HttpExtractorCheckBuilder[String](s => "", HttpPhase.HeadersReceived) {
  def find = new MatcherCheckBuilder[HttpCheck, Response, String](httpCheckBuilderFactory, fragmentExtractorFactory)
}

private[uaa] class JsonTokenCheckBuilder extends HttpExtractorCheckBuilder[String](s => "", HttpPhase.CompletePageReceived) {
  def find = new MatcherCheckBuilder[HttpCheck, Response, String](httpCheckBuilderFactory, jsonExtractorFactory)
}

/**
 */
object OAuthComponents {
  private val plainHeaders = Map(
    "Accept" -> "application/json",
    "Content-Type" -> "application/x-www-form-urlencoded")

  private val jsonHeaders = Map(
    "Accept" -> "application/json",
    "Content-Type" -> "application/x-www-form-urlencoded")

  /**
   * Performs an oauth token request as the specific client and saves the returned token
   * in the client session under the key "access_token".
   *
   */
  def clientCredentialsAccessTokenRequest(
    username: String, password: String, client_id: String, scope: String): ChainBuilder = {

    chain.exec(
      http("Client Credentials Token Request")
        .post("/oauth/token")
        .basicAuth(username, password)
        .param("client_id", client_id)
        .param("scope", scope)
        .param("grant_type", "client_credentials")
        .headers(plainHeaders)
        .check(status.is(200), jsonToken.saveAs("access_token")))
  }

  /**
   * Action which performs an implicit token request as VMC client.
   *
   * Requires a username and password in the session.
   */
  def vmcLogin(scope: String = "read"): ChainBuilder = vmcLogin("${username}", "${password}", scope)

  /**
   * Single vmc login action with a specific username/password and scope
   */
  def vmcLogin(username: String, password: String, scope: String): ChainBuilder = {
    chain.exec(
      http("VMC login")
        .post("/oauth/authorize")
        .param("client_id", "vmc")
        .param("scope", scope)
        .param("credentials", """{"username":"%s","%s":"password"}""".format(username, password))
        .param("redirect_uri", "uri:oauth:token")
        .param("response_type", "token")
        .headers(plainHeaders)
        .check(status.is(302), fragmentToken.saveAs("access_token")))
  }

  /**
   * Action which performs an authorization code token request as "app" client.
   *
   * Requires a username and password in the session.
   */
  def authorizationCodeLogin(scope: String = "read"): ChainBuilder = authorizationCodeLogin("${username}", "${password}", scope)

  def authorizationCodeLogin(username: String, password: String, scope: String): ChainBuilder = {
    chain
      .exec(
        http("initialize")
          .post("/oauth/authorize")
          .param("client_id", "app")
          .param("scope", "read")
          .param("redirect_uri", "uri:oauth:token")
          .param("response_type", "code")
          .headers(plainHeaders)
          .check(status.is(302)))
      .exec(
        http("login")
          .post("/login.do")
          .param("username", username)
          .param("password", password)
          .headers(plainHeaders)
          .check(status.is(302), header("Location").saveAs("location")))
      .exec((s: Session) => {
        var location = s.getAttribute("location")
        println("Login redirected to " + location)
        s
      })
      .exec(
        http("reload")
          .get("/oauth/authorize")
          .headers(plainHeaders)
          .check(status.is(200)))
      .exec(
        http("approve")
          .post("/oauth/authorize")
          .param("user_oauth_approval", "true")
          .headers(plainHeaders)
          .check(status.is(302), header("Location").saveAs("location")))
      .exec((s: Session) => {
        var code = s.getTypedAttribute[String]("location")
        println("Authorize redirected to " + code)
        code = code.substring(code.indexOf("code=") + 5)
        if (code.contains("&")) {
          code = code.substring(0, code.indexOf("&") - 1)
        }
        println("Auth code " + code)
        s.setAttribute("code", code)
      })
      .exec(
        http("get token")
          .post("/oauth/token")
          .basicAuth("app", "appclientsecret")
          .param("client_id", "app")
          .param("code", "${code}")
          .param("redirect_uri", "uri:oauth:token")
          .param("grant_type", "authorization_code")
          .headers(jsonHeaders)
          .check(status.is(200)))

  }

}
