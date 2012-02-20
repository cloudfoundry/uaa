package uaa

import com.excilys.ebi.gatling.http.Predef.httpConfig

/**
 */
object Config {
	val urlBase = sys.env.getOrElse("GATLING_UAA_BASE", "http://localhost:8080/uaa")

	def uaaHttpConfig = httpConfig.baseURL(urlBase)

}
