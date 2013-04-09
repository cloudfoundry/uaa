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
import com.excilys.ebi.gatling.core.check.{CheckBuilder, ExtractorFactory, MatcherCheckBuilder}
import com.excilys.ebi.gatling.core.structure.ChainBuilder
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.http.check.HttpCheck
import com.excilys.ebi.gatling.http.check.HttpExtractorCheckBuilder
import com.excilys.ebi.gatling.http.request.HttpPhase

import OAuthCheckBuilder._
import com.excilys.ebi.gatling.core.action.builder.ActionBuilder
import com.excilys.ebi.gatling.http.response.ExtendedResponse
import bootstrap._

/**
 * Checks for the presence of an access token or authorization code in the fragment/parameters of the Location header
 * or in the JSON body
 */
object OAuthCheckBuilder {
  private val fragmentTokenPattern = Pattern.compile(".*#.*access_token=([^&]+).*")
  private val jsonBodyTokenPattern = Pattern.compile(""""access_token":"(.*?)"""")
  private val authorizationCodePattern = Pattern.compile(".*code=([^&]+).*")

  def fragmentToken = new FragmentTokenCheckBuilder

  def jsonToken = new JsonTokenCheckBuilder

  // Get round Gatling bug #609
  def locationHeader = new LocationHeaderCheckBuilder

  // Allows saving of the auth code. Should only fail if response is a redirect with no auth code in the location
  def authCode = new AuthCodeCheckBuilder

  private[uaa] def fragmentExtractorFactory: ExtractorFactory[ExtendedResponse, String, String] = { (response: ExtendedResponse) =>
    (expression: String) =>
      val location = response.getHeader("Location")
      if (location != null) {
        val matcher = fragmentTokenPattern.matcher(location)

        if (matcher.find()) Some(matcher.group(1)) else None
      } else None
  }

  private[uaa] def authCodeExtractorFactory: ExtractorFactory[ExtendedResponse, String, String] = { (response: ExtendedResponse) =>
    (expression: String) =>
      val location = response.getHeader("Location")
      if (location != null) {
        val matcher = authorizationCodePattern.matcher(location)
        if (matcher.find()) Some(matcher.group(1)) else None
      } else Some("NoLocationNoCode")

  }

  private[uaa] def jsonExtractorFactory: ExtractorFactory[ExtendedResponse, String, String] = { (response: ExtendedResponse) =>
    (expression: String) =>
      val matcher = jsonBodyTokenPattern.matcher(response.getResponseBody())

      if (matcher.find()) Some(matcher.group(1)) else None
  }

  // Only used for saving the location header (status code can be used to check for a redirect)
  private[uaa] def locationHeaderExtractorFactory: ExtractorFactory[ExtendedResponse, String, String] = response => expression => {
    if (response.getStatusCode() != 302)
      println("Response is not a redirect")
    Option(response.getHeader("Location")) orElse(Some("No location header found"))
  }
}

private[uaa] class FragmentTokenCheckBuilder extends HttpExtractorCheckBuilder[String, String](s => "", HttpPhase.HeadersReceived) {
  def find = new MatcherCheckBuilder[HttpCheck[String], ExtendedResponse, String, String](httpCheckBuilderFactory, fragmentExtractorFactory)
}

private[uaa] class JsonTokenCheckBuilder extends HttpExtractorCheckBuilder[String, String](s => "", HttpPhase.CompletePageReceived) {
  def find = new MatcherCheckBuilder[HttpCheck[String], ExtendedResponse, String, String](httpCheckBuilderFactory, jsonExtractorFactory)
}

private[uaa] class AuthCodeCheckBuilder extends HttpExtractorCheckBuilder[String,String](s => "", HttpPhase.HeadersReceived) {
  def find = new MatcherCheckBuilder[HttpCheck[String], ExtendedResponse, String, String](httpCheckBuilderFactory, authCodeExtractorFactory)
}

private[uaa] class LocationHeaderCheckBuilder extends HttpExtractorCheckBuilder[String, String](s => "", HttpPhase.HeadersReceived) {
  def find = new MatcherCheckBuilder[HttpCheck[String], ExtendedResponse, String, String](httpCheckBuilderFactory, locationHeaderExtractorFactory)
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

  def haveAuthCode: (Session => Boolean) = _.isAttributeDefined("code")

  def haveAccessToken : (Session => Boolean) = _.isAttributeDefined("access_token")

  def clearCookies : (Session => Session) = _.removeAttribute("gatling.http.cookies")

  def saveLocation(): CheckBuilder[HttpCheck[String], ExtendedResponse, String] = locationHeader.saveAs("location")

  def statusIs(status:Int) : (Session => Boolean) = _.getAttribute("status").toString.toInt == status

  /**
   * Performs an oauth token request as the specific client and saves the returned token
   * in the client session under the key "access_token".
   */
  def clientCredentialsAccessTokenRequest(
    username: String, password: String, client_id: String, scope: String = ""): ActionBuilder =
      http("Client Credentials Token Request")
        .post("/oauth/token")
        .basicAuth(username, password)
        .param("client_id", client_id)
//        .param("scope", scope)
        .param("grant_type", "client_credentials")
        .headers(plainHeaders)
        .check(status.is(200), jsonToken.saveAs("access_token"))

  /**
   * Single vmc login action with a specific username/password
   */
  def vmcLogin(username: String = "${username}", password: String = "${password}"): ActionBuilder =
    vmcAction("CF login", username, password)
      .check(status is 200, jsonToken.saveAs("access_token"))

  def vmcLoginBadPassword(username: String = "${username}"): ActionBuilder =
    vmcAction("CF failed login - bad password", username, "pXssword")
      .check(status is 401)

  def vmcLoginBadUsername(): ActionBuilder =
    vmcAction("CF failed login - no user", "idontexist", "password")
      .check(status is 401)

  private def vmcAction(name: String, username: String, password: String) =
    http(name)
      .post("/oauth/token")
      .param("username", username)
      .param("password", password)
      .param("grant_type", "password")
      .basicAuth("cf", "")
      .header("Accept", "application/json")

  def login: ActionBuilder = login("${username}", "${password}")

  def login(username: String, password: String): ActionBuilder =
    http("Login")
    .post("/login.do")
    .param("username", username)
    .param("password", password)
    .headers(plainHeaders)
    .check(status.is(302), saveLocation())

  def logout = exec(
      http("Logout")
        .get("/logout.do")
        .headers(plainHeaders)
        .check(status.is(302), saveLocation())
    )
    .exec(
      http("Logged Out")
        .get("${location}")
        .headers(plainHeaders)
        .check(status.in(Seq(200,302))))
    .exec(clearCookies)

  /**
   * Action which performs an authorization code token request as a given client.
   *
   * Requires a username and password in the session.
   */
  def authorizationCodeLogin(client:Client): ChainBuilder = authorizationCodeLogin("${username}", "${password}", client)

  def authorizationCodeLogin(username: String, password: String, client:Client): ChainBuilder = {
    val redirectUri = client.redirectUri.getOrElse(throw new RuntimeException("Client does not have a redirectUri"))

     exec(
        http("Initial Request To Root")
           .get("/").check(status.is(302)))
        .exec(http("Authorization Endpoint")
          .get("/oauth/authorize")
          .queryParam("client_id", client.id)
//          .queryParam("scope", client.scopes.mkString(" "))
          .queryParam("redirect_uri", redirectUri)
          .queryParam("response_type", "code")
          .check(status.is(302)))
      .exec(login(username, password))
//      .exec((s: Session) => {
//        var location = s.getAttribute("location")
//        println("Login redirected to " + location)
//        s
//      })
      .exec(
        http("Reload after login")
          .get("${location}")
          .check(status.saveAs("status"), authCode.saveAs("code")))
      .doIf(statusIs(200))(exec( // Not auto-approved, so we do the approval page
        http("Authorization Approval")
          .post("/oauth/authorize")
          .param("user_oauth_approval", "true")
          .check(status.is(302), authCode.saveAs("code"))))
      .exec(clearCookies(_))
      .doIf(haveAuthCode) {exec(
        http("Access Token Request")
          .post("/oauth/token")
          .basicAuth(client.id, client.secret)
          .param("client_id",client.id)
          .param("code", "${code}")
          .param("redirect_uri", redirectUri)
          .param("grant_type", "authorization_code")
          .headers(jsonHeaders)
          .check(status.is(200)))
     }

  }

}
