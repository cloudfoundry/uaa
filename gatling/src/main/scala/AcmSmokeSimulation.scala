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
   * Creates n objects with nUsers assigned to each of the standard (base data) permissions
   * Reads the object nReads times
   */
  def createObjects(n: Int, nUsers: Int, nGroups: Int, nReads: Int=100) = scenario("Bash ACM Object Creation")
    .loop(
      chain.exec(createObject(Seq("app_space"), stdPermissions map (s => (s, acmUsers.take(nUsers))) toMap))
      .loop(
        chain.exec(getObject("${acm_object_id}"))
        .pause(10,100, TimeUnit.MILLISECONDS)
      ).times(nReads)
  ).during(Duration)

  /**
   * The main simulation method defining scenarios to be run, number of users.
   */
  def apply = {
    Seq(
//        createPermissionSets(10).configure users 1 protocolConfig acmHttpConfig,
        createObjects(10, 5, 2, 1).configure users 1 protocolConfig acmHttpConfig
    )
  }

}
