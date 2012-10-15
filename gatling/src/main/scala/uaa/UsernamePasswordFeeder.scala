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

import com.excilys.ebi.gatling.core.feeder.Feeder

/**
 * Counter-based username generator with fixed password, defaulting to "password".
 */
case class UsernamePasswordFeeder(prefix: String = "shaun", password: String = "password", resetAfter: Int = Config.nUsers) extends Feeder {
  var counter = 0

  def next = {
    if (counter == resetAfter)
      counter = 1
    counter += 1
    Map("username" -> (prefix + counter), "password" -> password)
  }

  def hasNext = true
}

