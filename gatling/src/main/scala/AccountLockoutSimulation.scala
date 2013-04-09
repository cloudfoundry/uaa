import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.UniqueUsernamePasswordFeeder
import uaa.OAuthComponents._

import bootstrap._
/**
 * Simulates logins with an incorrect password until the account is locked out,
 * followed by an attempt with the correct password (which should fail)
 */
class AccountLockoutSimulation extends Simulation {

  val lockoutScenario = scenario("Account Lockout")
      .feed(UniqueUsernamePasswordFeeder(users))
      .repeat(10)(
        exec(vmcLoginBadPassword())
      )
      .pause(61*5) // 5 mins 5 secs
      .exec((s:Session) => {
        s.setAttribute("password", "password") // use the right password
      })
      .exec(vmcLogin())

  setUp (
      lockoutScenario.users(5).protocolConfig(uaaHttpConfig)
  )
}
