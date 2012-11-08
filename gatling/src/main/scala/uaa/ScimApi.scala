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

import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.core.structure.ChainBuilder

import uaa.OAuthComponents._

import uaa.Config._
import com.excilys.ebi.gatling.http.Predef._

/**
 * @author Luke Taylor
 * @author Vidya Valmikinathan
 */
object ScimApi {
  def scimClientLogin() = clientCredentialsAccessTokenRequest(
    username = scimClient.id,
    password = scimClient.secret,
    client_id = scimClient.id)

  /**
   * Creates 'n' users by invoking the SCIM API.
   *
   * Usernames can optionally be prefixed
   */
  def createScimUsers(userFeeder: UniqueUsernamePasswordFeeder): ChainBuilder =
    chain.exec(
      scimClientLogin()
    )
    .doIf(haveAccessToken)(
      chain.loop(
      chain.feed(userFeeder)
        .exec((s: Session) => {println("Creating user: %s" format(s.getAttribute("username"))); s})
        .exec(createUser)
      ).asLongAs(s => {userFeeder.hasNext})
    )

  def createScimGroups(groupFeeder: UniqueGroupFeeder): ChainBuilder =
    chain.exec(
      scimClientLogin()
    )
    .doIf(haveAccessToken)(
      chain.loop(
        chain.feed(groupFeeder)
          .exec(getMemberUser("memberName_1", "memberId_1"))
          .exec(getMemberUser("memberName_2", "memberId_2"))
          .exec(createGroup)
      ).asLongAs(s => {groupFeeder.hasNext})
    )

  def getMemberUser(input: String, output: String) = {
    http("Find user by name")
      .get("/Users")
      .queryParam("attributes", "id")
      .queryParam("filter","userName eq '${" + input + "}'")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(""""id":"(.*?)"""").saveAs(output))
  }

  def getMemberGroup(input: String, output:String) = {
    http("Find user by name")
      .get("/Groups")
      .queryParam("attributes", "id")
      .queryParam("filter","displayName eq '${" + input + "}'")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(""""id":"(.*?)"""").saveAs(output))
  }


  /**
   * Creates a SCIM user.
   *
   * A suitable access token must already be available in the session, as well as username and password values.
   *
   */
  def createUser =
      http("Create User")
        .post("/Users")
        .header("Authorization", "Bearer ${access_token}")
        .body("""{"name":{"givenName":"Shaun","familyName":"Sheep","formatted":"Shaun the Sheep"},"password":"${password}","userName":"${username}","emails":[{"value":"${username}@blah.com"}]}""")
        .asJSON
        .check(status.is(201), regex(""""id":"(.*?)"""").saveAs("__scimUserId"))

  /**
   * Creates a SCIM group.
   *
   * A suitable access token must already be available in the session, as well as displayName and memberIds.
   *
   */
  def createGroup =
      http("Create Group")
        .post("/Groups")
        .header("Authorization", "Bearer ${access_token}")
        .body("""{"displayName":"${displayName}","members":[{"value":"${memberId_1}"},{"value":"${memberId_2}"}]}""")
        .asJSON
        .check(status.is(201), regex(""""id":"(.*?)"""").saveAs("__scimGroupId"))


  /**
   * Finds a user and stores their ID in the session as `userId`. Uses the session attribute "username" for the
   * search.
   */
  def findUserByName (input: String) = {
    http("Find user by name")
      .get("/Users")
      .queryParam("attributes", "id")
      .queryParam("filter","userName eq '${" + input + "}'")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(""""id":"(.*?)"""").saveAs("userId"))
  }

  def findGroupByName =
    http("Find group by name")
      .get("/Groups")
      .queryParam("attributes", "id,members")
      .queryParam("filter","displayName eq '${displayName}'")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(""""id":"(.*?)"""").saveAs("groupId"), regex(""""value":"(.*?)"""").saveAs("memberId"))


  /**
   * Pulls a user by  `userId` and stores the data under `scimUser`
   */
  def getUser =
    http("Get User")
      .get("/Users/${userId}")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(".*").saveAs("scimUser"))

  def getMemberUser =
    http("Get Member User")
      .get("/Users/${memberId}")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(".*").saveAs("memberUser"), regex(""""id":"(.*?)"""").saveAs("memberId"))

  def getGroup =
    http("Get Group")
      .get("/Groups/${groupId}")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(".*").saveAs("scimGroup"), regex("""\[.*?}\]""").saveAs("memberJson"))

  def getMemberGroup =
    http("Get Member Group")
      .get("/Groups/${memberId}")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(".*").saveAs("memberGroup"), regex(""""id":"(.*?)"""").saveAs("memberId"))


  /**
   * Performs an update using the data in `scimUser`.
   */
  def updateUser =
    http("Update user")
      .put("/Users/${userId}")
      .header("Authorization", "Bearer ${access_token}")
      .body("${scimUser}")
      .asJSON
      .check(status.is(204))

  def addGroupMember (member: String) =
    http("Add member to group")
      .put("/Groups/${groupId}")
      .header("Authorization", "Bearer ${access_token}")
      .header("If-Match", "*")
      .body((s: Session) => getUpdatedGroupJson(s.getAttribute("scimGroup").toString, s.getAttribute("memberJson").toString, s.getAttribute(member).toString))
      .asJSON
      .check(status.is(200), regex(".*").saveAs("scimGroup"), regex("""\[.*?}\]""").saveAs("memberJson"))

  def nestGroup =
    http("Add member to group")
      .put("/Groups/${groupId}")
      .header("Authorization", "Bearer ${access_token}")
      .header("If-Match", "*")
      .body((s: Session) => getUpdatedGroupJson(s.getAttribute("scimGroup").toString,
                                                s.getAttribute("memberJson").toString,
                                                s.getAttribute("memberId").toString,
                                                "GROUP"))
      .asJSON
      .check(status.is(200), regex(""""id":"(.*?)"""").saveAs("memberId"))


  def getUpdatedGroupJson(groupJson: String, memberJson: String, newMemberId: String, memberType: String = "USER") = {
    val updatedMembersJson = """[ %s, { "value": "%s", "type": "%s", "authorities": ["READ"] } ]""" format(memberJson.substring(1).dropRight(1), newMemberId, memberType)
    val result = groupJson.replace(memberJson, updatedMembersJson)
//    if (memberType == "USER") println("\n\n>>>> " + result)
    result
  }

  def changePassword =
      http("Change Password")
        .put("/Users/${userId}/password")
        .header("Authorization", "Bearer ${access_token}")
        .body("""{"password":"${password}"}""")
        .asJSON
        .check(status.is(204))

}
