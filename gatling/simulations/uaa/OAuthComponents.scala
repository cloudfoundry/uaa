package uaa

import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.core.action.builder.AbstractActionBuilder
import com.ning.http.client.Response
import com.excilys.ebi.gatling.http.request.HttpPhase
import com.excilys.ebi.gatling.core.check._
import com.excilys.ebi.gatling.http.check.{HttpCheck, HttpCheckBuilder}
import java.util.regex.Pattern

/**
 * Checks for the presence of a token in the fragment of the Location header
 */
private[uaa] object FragmentTokenCheckBuilder {
	val tokenFragment = Pattern.compile(".*#.*access_token=([^&]+).*")

	def token = new FragmentTokenCheckBuilder

	private def findExtractorFactory: ExtractorFactory[Response, String] = { (response: Response) => (expression: String) =>
		val matcher = tokenFragment.matcher(response.getHeader("Location"))

		if (matcher.find()) Some(matcher.group(1)) else None
	}
}

import FragmentTokenCheckBuilder._

class FragmentTokenCheckBuilder extends HttpCheckBuilder[String](s => "", HttpPhase.HeadersReceived) {
	def find = new CheckOneBuilder[HttpCheck[String], Response, String](httpCheckBuilderFactory, findExtractorFactory)
}

/**
 */
object OAuthComponents {
	private val plainHeaders = Map(
		"Accept" -> "application/json",
		"Content-Type" -> "application/x-www-form-urlencoded")

	/**
	 * Performs an oauth token request as the specific client and saves the returned token
	 * in the client session under the key "access_token".
	 *
	 */
	def clientCredentialsAccessTokenRequest(
				username: String, password: String, client_id: String, scope: String): AbstractActionBuilder = {

		http("Client Credentials Token Request")
				.post("/oauth/token")
				.basicAuth(username, password)
				.param("client_id", client_id)
				.param("scope", scope)
				.param("grant_type", "client_credentials")
				.headers(plainHeaders)
				.check(status.is(200), regex(""""access_token":"(.*?)"""").saveAs("access_token"))
	}

	/**
	 * Action which performs an implicit token request as VMC client.
	 *
	 * Requires a username and password in the session.
	 */
	def vmcLogin(scope: String = "read"): AbstractActionBuilder = vmcLogin("${username}", "${password}", scope)

	/**
	 * Single vmc login action with a specific username/password and scope
	 */
	def vmcLogin(username: String, password: String, scope: String): AbstractActionBuilder = {
		http("VMC login")
				.post("/oauth/authorize")
				.param("client_id", "vmc")
				.param("scope", scope)
				.param("credentials", """{"username":"%s","%s":"password"}""".format(username, password))
				.param("redirect_uri", "uri:oauth:token")
				.param("response_type", "token")
				.headers(plainHeaders)
				.check(status.is(302), token.saveAs("access_token"))
	}


}
