
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.ScimApi._
import uaa.UaaApi._
import uaa.OAuthComponents._
import uaa.{UniqueGroupFeeder, UniqueUsernamePasswordFeeder}
import bootstrap._

class UaaUserDataCreationSimulation extends Simulation {
  val registerClients = scenario("Register clients")
    .exec(adminClientLogin())
    .doIf(haveAccessToken)(exec(
        registerClient(scimClient)
      )
      .exec(
        registerClient(appClient)
      )
    )

  def createUsers = scenario("Create users")
    .pause(5)
    .exec(createScimUsers(UniqueUsernamePasswordFeeder(users)))

  setUp(
      registerClients.users(1).protocolConfig(uaaHttpConfig)
      , createUsers.users(5).protocolConfig(uaaHttpConfig)
    )
}

class UaaGroupDataCreationSimulation extends Simulation {
  val registerClients = scenario("Register clients")
    .exec(adminClientLogin())
    .doIf(haveAccessToken)(exec(
    registerClient(scimClient)
    )
    .exec(registerClient(appClient))
  )

  def createGroups = scenario("Create groups")
    .pause(5)
    .exec(createScimGroups(UniqueGroupFeeder()))

  setUp(
      registerClients.users(1).protocolConfig(uaaHttpConfig),
      createGroups.users(5).protocolConfig(uaaHttpConfig)
    )
}
