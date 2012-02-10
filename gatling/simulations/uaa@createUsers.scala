import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.core.feeder.Feeder
import com.excilys.ebi.gatling.script.GatlingSimulation
import java.util.concurrent.TimeUnit

class Simulation extends GatlingSimulation {

	val urlBase = sys.env.getOrElse("GATLING_UAA_BASE", "http://localhost:8080/uaa")

	val httpConf = httpConfig.baseURL(urlBase)

	val plainHeaders = Map(
		"Accept" -> "application/json",
		"Content-Type" -> "application/x-www-form-urlencoded")

	// Feeder which generates the usernames
	val feeder = new Feeder {
		var counter = 0

		def next = {
			counter += 1
			Map("username" -> ("joe" + counter))
		}
	}

	val createUsers = scenario("Create user")
				.exec(
						http("getToken")
								.post("/oauth/token")
								.basicAuth("scim", "scimsecret")
								.param("client_id", "scim")
								.param("scope", "write password")
								.param("grant_type", "client_credentials")
								.headers(plainHeaders)
								.check(status.is(200), regex(""""access_token":"(.*?)"""").saveAs("access_token"))
				)
				.loop(
						chain.feed(feeder)
						.exec((s: Session) => {
								println("Creating user " + s.getAttribute("username"))
								s
						})
						.exec(
							http("createUser")
								.post("/User")
								.header("Authorization", "Bearer ${access_token}")
								.body("""{"name":{"givenName":"Joe","familyName":"User","formatted":"Joe User"},"userName":"${username}","emails":[{"value":"${username}@blah.com"}]}""")
								.asJSON()
								.check(status.is(201), regex(""""id":"(.*?)"""").saveAs("userId"))
						)
						.exec( // set the password to "password"
							http("changePassword")
								.put("/User/${userId}/password")
								.header("Authorization", "Bearer ${access_token}")
								.body("""{"password":"password"}""")
								.asJSON()
								.check(status.is(204))
						)
						.pause(50,200, TimeUnit.MILLISECONDS)
				).times(10)

	runSimulation(createUsers.configure users 10 protocolConfig httpConf)
}
