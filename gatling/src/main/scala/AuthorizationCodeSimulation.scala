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
import com.excilys.ebi.gatling.app.Simulation
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.OAuthComponents._
import uaa.Config._
import uaa.UsernamePasswordFeeder

class AuthorizationCodeSimulation extends Simulation {

  def apply = {
    val scn = scenario("Authorization Code Login")
      .feed(UsernamePasswordFeeder())
      .loop(
        // Uses the session values for username/password provided by the feeder
        authorizationCodeLogin()
          .pause(1, 2)).during(60)

    Seq(scn.configure users 10 ramp 10 protocolConfig uaaHttpConfig)
  }
}
