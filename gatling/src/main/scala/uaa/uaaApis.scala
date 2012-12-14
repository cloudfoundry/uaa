package uaa

import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.core.Predef._
import uaa.Config._
import uaa.OAuthComponents._

case class User(username: String, password: String) {
  override def toString = {
    username
  }
}

case class Group(displayName: String, members: Seq[User])

case class Client(id: String, secret: String, scopes: Seq[String], resources: Seq[String], authorities: Seq[String], grants: Seq[String] = Seq("client_credentials"), redirectUri: Option[String] = None) {
  val toJson = {
    val redirectJson = redirectUri match {
      case Some(uri) =>"\n\"redirect_uri\" : [\"%s\"],\n".format(uri)
      case None => ""
    }
    """{
          "client_id" : "%s",
          "client_secret" : "%s", %s
          "scope" : [%s],
          "resource_ids" : [%s],
          "authorities" : [%s],
          "authorized_grant_types" : [%s]
    }
    """.format(id, secret, redirectJson, fmt(scopes), fmt(resources), fmt(authorities), fmt(grants))
  }

  private def fmt(seq: Seq[String]) = seq.mkString("\"", "\",\"", "\"")
}


object UaaApi {
  /**
   * Shortcut for getting an access token as the default bootstrap admin client
   */
  def adminClientLogin() =
    clientCredentialsAccessTokenRequest(admin_client_id, admin_client_secret, admin_client_id)


  def registerClient(client: Client) =
    http("Register Client")
      .post("/oauth/clients")
      .header("Authorization", "Bearer ${access_token}")
      .body(client.toJson)
    .asJSON
    .check(status is 201)
}
