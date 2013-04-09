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
import com.excilys.ebi.gatling.core.action.builder.ActionBuilder
import bootstrap._

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
    exec(
      scimClientLogin()
    )
    .doIf(haveAccessToken)(
      asLongAs(s => {userFeeder.hasNext}) {
      feed(userFeeder)
        .exec((s: Session) => {println("Creating user: %s" format(s.getAttribute("username"))); s})
        .exec(createUser)
      }
    )

  def createScimGroups(groupFeeder: UniqueGroupFeeder): ChainBuilder =
    exec(
      scimClientLogin()
    )
    .doIf(haveAccessToken)(
      asLongAs(s => {groupFeeder.hasNext}) {
        feed(groupFeeder)
          .exec(findUserByName("memberName_1", "memberId_1"))
          .exec(findUserByName("memberName_2", "memberId_2"))
          .exec(createGroup)
      }
    )

  /**
   * Finds a user and stores their ID in the session as `userId`. Uses the session attribute "username" for the
   * search.
   */
  def findUserByName(input: String, output: String) : ActionBuilder = {
    http("Find user by name")
      .get("/Users")
      .queryParam("attributes", "id")
      .queryParam("filter","userName eq '${" + input + "}'")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(""""id":"(.*?)"""").saveAs(output))
  }

  def findUserByName (input: String) : ActionBuilder = {
    findUserByName(input, "userId")
  }

  /**
   * Find a group by name
   * @param input name of the session attribute that has the group name to lookup
   * @param output name of the session attribute in which to store the group's id
   * @return
   */
  def findGroupByName(input: String, output:String) : ActionBuilder = {
    http("Find user by name")
      .get("/Groups")
      .queryParam("attributes", "id")
      .queryParam("filter","displayName eq '${" + input + "}'")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(""""id":"(.*?)"""").saveAs(output))
  }

  def findGroupByName : ActionBuilder = {
    findGroupByName("displayName", "groupId")
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
   * Create a SCIM group.
   */
  def createGroup =
      http("Create Group")
        .post("/Groups")
        .header("Authorization", "Bearer ${access_token}")
        .body("""{"displayName":"${displayName}","members":[{"value":"${memberId_1}"},{"value":"${memberId_2}"}]}""")
        .asJSON
        .check(status.is(201), regex(""""id":"(.*?)"""").saveAs("__scimGroupId"))

  /**
   * Pulls a user by  `userId` and stores the data under `scimUser`
   */
  def getUser (prefix: String) : ActionBuilder =
    http("Get User")
      .get("/Users/${userId}")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(".*").saveAs(prefix + "User"), regex(""""id":"(.*?)"""").saveAs(prefix + "Id"))

  def getUser : ActionBuilder = {
    getUser("user")
  }

  /**
   * Fetch a group using SCIM APIs.
   *
   * @param prefix prefix for session attributes to which to store the fetched group
   * @return
   */
  def getGroup (prefix: String) : ActionBuilder =
    http("Get Group")
      .get("/Groups/${groupId}")
      .header("Authorization", "Bearer ${access_token}")
      .asJSON
      .check(status.is(200), regex(".*").saveAs("scimGroup"), regex("""\[.*?}\]""").saveAs("memberJson"), regex(""""id":"(.*?)"""").saveAs(prefix + "Id"))

  def getGroup : ActionBuilder = {
    getGroup("group")
  }

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

  /**
   * Add a user as a member to a group
   * @param member the id of the user to add
   * @return
   */
  def addGroupMember (member: String) : ActionBuilder =
    http("Add member to group")
      .put("/Groups/${groupId}")
      .header("Authorization", "Bearer ${access_token}")
      .header("If-Match", "*")
      .body((s: Session) => getUpdatedGroupJson(s.getAttribute("scimGroup").toString, s.getAttribute("memberJson").toString, s.getAttribute(member).toString))
      .asJSON
      .check(status.is(200), regex(".*").saveAs("scimGroup"), regex("""\[.*?}\]""").saveAs("memberJson"))

  /**
   * Add a group as member to another group.
   */
  def nestGroup : ActionBuilder =
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

  /**
   * Add a member to a given JSON representation of a group
   * @param groupJson current JSON representation of a group
   * @param memberJson substring of groupJson that lists current members of the group
   * @param newMemberId id of new member to be added
   * @param memberType 'USER' or 'GROUP'
   * @return JSON representation of group that can be used in a PUT request body
   */
  def getUpdatedGroupJson(groupJson: String, memberJson: String, newMemberId: String, memberType: String = "USER") = {
    val updatedMembersJson = """[ %s, { "value": "%s", "type": "%s", "authorities": ["READ"] } ]""" format(memberJson.substring(1).dropRight(1), newMemberId, memberType)
    groupJson.replace(memberJson, updatedMembersJson)
  }

  def changePassword =
      http("Change Password")
        .put("/Users/${userId}/password")
        .header("Authorization", "Bearer ${access_token}")
        .body("""{"password":"${password}"}""")
        .asJSON
        .check(status.is(204))

}
