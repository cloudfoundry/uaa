import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.UniqueUsernamePasswordFeeder
import uaa.OAuthComponents._

/**
 * Simulates logins with an incorrect password until the account is locked out,
 * followed by an attempt with the correct password (which should fail)
 */
class AccountLockoutSimulation extends Simulation {

  val lockoutScenario = scenario("Account Lockout")
      .feed(UniqueUsernamePasswordFeeder(users, Some("wrongpass")))
      .loop(
        chain.exec(vmcLogin("${username}", "${password}", "read", 401))
      )
      .times(10)
      .pause(60*5) // 5 mins
      .exec((s:Session) => {
        s.setAttribute("password", "password") // use the right password
      })
      .exec(vmcLogin())


  def apply = {
    Seq(
      lockoutScenario.configure users 5 protocolConfig uaaHttpConfig
    )
  }
}
