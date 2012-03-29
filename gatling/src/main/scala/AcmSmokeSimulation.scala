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

import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import acm.Config._
import acm.AcmApi._
import java.util.concurrent.TimeUnit


import AcmBaseData._


class AcmSmokeSimulation extends Simulation {
  val Duration = 60


  /**
   * Creates permission sets and with the specified number of randomly-named permissions,
   * reads the permission set nReads times then deletes it
   */
  def createPermissionSets(nPermissions: Int, nReads: Int=100) = scenario("Permission Set creation with %s permissions".format(nPermissions))
    .loop(
      chain.exec(createRandomPermissionSet(nPermissions))
      .loop(chain
        .exec(getPermissionSet("${permission_set}"))
      ).times(100)
      .exec(deletePermissionSet("${permission_set}"))
  ).during(Duration)

  /**
   * Creates objects with nUsers and nGroups assigned to each of the standard (base data) permissions
   * Reads the object, the users with permissions on an object, and then checks the object access nReads times
   * for each user with three permission values.
   */
  def createObjects(nUsers: Int, nGroups: Int, nReads: Int=100) = scenario("Object Creation and access checks")
    .loop(
      chain.exec(createObject(Seq("app_space"), stdPermissions map (s => (s, acmUsers.take(nUsers) ::: acmGroups.take(nGroups))) toMap))
        .exec(getObject("${acm_object_id}"))
        .exec(
          http("Get Object Users")
            .get("/objects/${acm_object_id}/users")
            .basicAuth(acmUser, acmPassword)
            .check(status is(200))
        )
        .loop(
          chain.loop(
            chain.feed(AcmBaseData.userFeeder(nUsers-1))
            .exec(
              http("Check Access")
                .get("/objects/${acm_object_id}/access?id=${acm_user}&p=%s".format(stdPermissions.take(3).mkString(",")))
                .basicAuth(acmUser, acmPassword)
                .check(status is(200))
             )
            .pause(10,100, TimeUnit.MILLISECONDS)
          ).times(nUsers)
        ).times(nReads)
  ).during(Duration)


  /**
   * The main simulation method defining scenarios to be run, number of users.
   */
  def apply = {
    Seq(
//        createPermissionSets(10).configure users 1 protocolConfig acmHttpConfig,
        createObjects(5, 3, 10).configure users 1 protocolConfig acmHttpConfig
    )
  }

}
