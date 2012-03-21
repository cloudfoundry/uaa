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

import com.excilys.ebi.gatling.core.feeder.Feeder
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.core.scenario.configuration.Simulation
import com.excilys.ebi.gatling.http.Predef._

import acm.AcmApi._
import acm.Config._
import java.util.concurrent.atomic.AtomicInteger

object AcmBaseData {
  // Standard permissions for the "app space"
  val stdPermissions = Seq("read_app", "update_app", "delete_app", "read_app_logs", "read_service", 
    "write_service", "add_user", "remove_user")

  // Standard list of users and groups for use in ACLs etc
  val acmUsers: List[String] = (1 to 1000 map (i => "acm_user_%s".format(i))).toList

  val acmGroups: List[String] = (1 to 1000 map (i => "g-acm_group_%s".format(i))).toList

  // Feeder for plugging standard user names into actions
  def acmUserFeeder = new Feeder {
    var count = -1

    def next = {
      count += 1
      Map("acm_user" -> acmUsers(count))
    }
  }
}

/**
 * Populates an empty ACM database with user and group data
 */
class AcmBaseDataCreationSimulation extends Simulation {

  import AcmBaseData._

  val createStandardAppSpace = scenario("Create Standard App Space")
    .exec(createPermissionSet("app_space", stdPermissions take 5))
    .exec(updatePermissionSet("app_space", stdPermissions))

  val createUsers = scenario("Create Standard Users")
    .loop(chain
      .feed(acmUserFeeder)
      .exec(createUser("${acm_user}"))
  ).times(100)

  val groupCount = new AtomicInteger(0)
  val groupUsersCount = new AtomicInteger(0)
  val MaxUsersPerGroup = 50
  
  val createGroups = scenario("Create Standard Groups")
    // Loop until we have enough users created
    .loop(
      chain.pause(1).exec(
        http("Get Max Required User")
        .get("/users/acm_user_%s".format(MaxUsersPerGroup))
        .basicAuth(acmUser, acmPassword)
        .check(status.saveAs("max_user_status")))
    ).asLongAs((s: Session) => {
      val status = s.getAttributeAsOption[Int]("max_user_status")
//      println("Status is " + status + "," + status.getClass)
      status == None || status == Some(404)
    })
    .loop(
        chain.exec((s: Session) => {
          val nUsers = groupUsersCount.incrementAndGet()  match {
            case x if (x % MaxUsersPerGroup == 0) => MaxUsersPerGroup
            case y => y % MaxUsersPerGroup
          }
          assert(nUsers > 0 && nUsers <= MaxUsersPerGroup)
          val users = acmUsers.take(nUsers).mkString("\"", "\",\"", "\"")
          s.setAttribute("group_count", groupCount.incrementAndGet())
           .setAttribute("group_users", users)
        })
        .exec(
          http("Create Standard Group")
          .post("/groups/g-acm_group_${group_count}")
          .body("""{"members": [${group_users}]}""")
          .basicAuth(acmUser, acmPassword)
          .check(status.is(200)))
      ).times(1000
  )

  def apply = {
    Seq(
      createStandardAppSpace.configure users 1 protocolConfig acmHttpConfig,
      createUsers.configure users 1 protocolConfig acmHttpConfig,
      createGroups.configure users 1 protocolConfig acmHttpConfig
    )
  }

}
