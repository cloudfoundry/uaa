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
import com.excilys.ebi.gatling.core.scenario.configuration.Simulation
import com.excilys.ebi.gatling.core.structure.ChainBuilder


import acm.AcmApi._
import acm.Config._

class AcmPermissionSetCreationSimulation extends Simulation {

  /**
   * recursive call to create a chain of n executors, creating sets with `start` to `start + n * incr`
   */
  def permissionSetCreationChain(cb: ChainBuilder, n: Int, start: Int, incr: Int=10): ChainBuilder = n match {
    case 0 => cb
    case _ => permissionSetCreationChain(cb.exec(createRandomPermissionSet(start)), n - 1, start + incr)
  }

  val createPermissionSets = scenario("Create Permission Sets")
      .insertChain(permissionSetCreationChain(ChainBuilder.chain, 100, 1, 1))

  def apply = {
    Seq(
      createPermissionSets.configure users 1 protocolConfig acmHttpConfig
    )
  }
}
