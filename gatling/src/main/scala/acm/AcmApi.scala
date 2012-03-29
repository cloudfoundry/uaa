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

import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.core.session.Session
import com.excilys.ebi.gatling.core.session.EvaluatableString
import java.util.UUID._
import com.excilys.ebi.gatling.core.action.builder.ActionBuilder

/**
 * Reusable ACM api calls
 */
object AcmApi {
  val PermissionSet = "permission_set"
  val ObjectId = "acm_object_id"
  val GroupId = "acm_group_id"
  
  val acmUser: EvaluatableString = s => Config.acm_user
  val acmPassword: EvaluatableString = s => Config.acm_password

  def createRandomPermissionSet(size: Int) =
    http("Create %s Permission Set".format(size))
      .post("/permission_sets")
      .basicAuth(acmUser, acmPassword)
      .body(genPermissions(size))
      .asJSON
      .check(status.is(200), jsonPath("/name").saveAs(PermissionSet))

  private def genPermissions(n: Int)(s: Session): String = {
    val name = "perm_set_%s".format(randomUUID())
    """{"name": "%s", "permissions": [%s]}""".format(name, formatSeq((1 to n) map (_ => "permission_%s".format(randomUUID()))))
  }

  def createPermissionSet(name: String, permissions: Seq[String], expectedStatus: Int = 200) =
    http("Create Permission Set")
      .post("/permission_sets")
      .basicAuth(acmUser, acmPassword)
      .body("""{"name": "%s", "permissions": [%s]}""".format(name, formatSeq(permissions)))
      .asJSON
      .check(status.is(expectedStatus))

  def getPermissionSet(name: String, expectedStatus: Int = 200) =
    http("Get Permission Set")
      .get("/permission_sets/%s".format(name))
      .basicAuth(acmUser, acmPassword)
      .check(status.is(expectedStatus))

  def updatePermissionSet(name: String, permissions: Seq[String]) =
    http("Update Permission Set")
      .put("/permission_sets/%s".format(name))
      .basicAuth(acmUser, acmPassword)
      .body("""{"name": "%s", "permissions": [%s]}""".format(name, formatSeq(permissions)))
      .asJSON
      .check(status.is(200))

  def deletePermissionSet(name: String) =
    http("Delete Permission Set")
      .delete("/permission_sets/%s".format(name))
      .basicAuth(acmUser, acmPassword)
      .check(status.is(200))

  def createUser(id: String) =
    http("Create User")
      .post("/users/%s".format(id))
      .basicAuth(acmUser, acmPassword)
      .check(status.is(200))

  def getUser(id: String) =
    http("Get User")
      .get("/users/%s".format(id))
      .basicAuth(acmUser, acmPassword)
      .check(status.is(200))

  def createObject(permissionSets: Seq[String], acl: Map[String, Seq[String]]) =
    http("Create ACM Object")
      .post("/objects")
      .basicAuth(acmUser, acmPassword)
      .body("""{"permission_sets": [%s], "acl": {%s} }""".format(formatSeq(permissionSets), formatAcl(acl)))
      .asJSON
      .check(status.is(200), jsonPath("/id").saveAs(ObjectId))
  
  def getObject(id: String) =
    http("Get ACM Object")
      .get("/objects/%s".format(id))
      .basicAuth(acmUser, acmPassword)
      .check(status.is(200))


  def createGroup(id: Option[String], members: Seq[String]): ActionBuilder =
    http("Create Group")
      .post(id match {
        case Some(s) => "/groups/%s".format(s)
        case None => "/groups"
      })
      .body("""{"members": [%s]}""".format(formatSeq(members)))
      .basicAuth(acmUser, acmPassword)
      .check(status.is(200), jsonPath("/id").saveAs(GroupId))

  def getGroup(id: String) =
    http("Get Group")
      .get("/groups/%s".format(id))
      .basicAuth(acmUser, acmPassword)
      .check(status.is(200))



  private def formatSeq(strings: Seq[String]) = strings.mkString("\"", "\",\"", "\"")

  private def formatAcl(acl: Map[String, Seq[String]]) =
    acl map {
      case (perm, users) => """ "%s": [%s]  """.format(perm, formatSeq(users))
    } mkString (",")

}
