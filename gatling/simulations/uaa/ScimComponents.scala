package uaa

import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.core.structure.ChainBuilder

/**
 */
object ScimComponents {

	/**
	 * Creates a SCIM user.
	 *
	 * A suitable access token must already be available in the session, as well as username and password values.
	 *
	 */
	val createScimUserChain: ChainBuilder = {
		chain.exec(
			http("createUser")
				.post("/User")
				.header("Authorization", "Bearer ${access_token}")
				.body("""{"name":{"givenName":"Joe","familyName":"User","formatted":"Joe User"},"userName":"${username}","emails":[{"value":"${username}@blah.com"}]}""")
				.asJSON()
				.check(status.is(201), regex(""""id":"(.*?)"""").saveAs("__scimUserId"))
		)
		.exec(
			http("changePassword")
				.put("/User/${__scimUserId}/password")
				.header("Authorization", "Bearer ${access_token}")
				.body("""{"password":"${password}"}""")
				.asJSON()
				.check(status.is(204))
		).exec((s: Session) => {
				s.removeAttribute("__scimUserId")
			}

		)

	}

}
