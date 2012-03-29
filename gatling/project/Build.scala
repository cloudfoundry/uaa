import collection.Seq
import sbt._
import Keys._

object GatlingPlugin {
  val gatling = TaskKey[Unit]("gatling")

  val gatlingVersion = SettingKey[String]("gatling-version")
  val gatlingResultsDirectory = SettingKey[String]("gatling-results-directory")
  val gatlingDataDirectory = SettingKey[String]("gatling-data-directory")
  val gatlingConfigFile = SettingKey[String]("gatling-config-file")

  lazy val gatlingSettings = Seq(
    gatlingVersion := "1.1.1-SNAPSHOT",
    fullClasspath in gatling <<= fullClasspath or (fullClasspath in Runtime),
    gatlingResultsDirectory <<= target(_.getAbsolutePath + "/gatling-results"),
    gatlingDataDirectory <<= (resourceDirectory in Compile).apply(_.getAbsolutePath),
    gatlingConfigFile <<= (resourceDirectory in Compile).apply(_.getAbsolutePath + "/gatling.conf"),

    libraryDependencies <++= (gatlingVersion) { gv => Seq(
      "com.excilys.ebi.gatling" % "gatling-app" % gv,
      "com.excilys.ebi.gatling" % "gatling-http" % gv,
      "com.excilys.ebi.gatling.highcharts" % "gatling-charts-highcharts" % gv)
    },

    gatling <<= (streams, gatlingResultsDirectory, gatlingDataDirectory, gatlingConfigFile, fullClasspath in gatling, classDirectory in Compile, runner in run)
        map { (s, grd, gdd, gcf, cp, cd, runner) => {
          val args = Array("--results-folder", grd,
                        "--data-folder", gdd,
                        "--config-file", gcf,
                        "--simulations-binaries-folder", cd.absolutePath)

          toError(runner.run("com.excilys.ebi.gatling.app.Gatling", Build.data(cp), args, s.log))
        }
    }
  )
}

object UaaGatlingBuild extends Build {

    import GatlingPlugin._

//    val mavenLocalRepo = "Local Maven Repository" at "file://" + Path.userHome.absolutePath +"/.m2/repository"

    val excilysReleaseRepo = "Excilys Release Repo" at "http://repository.excilys.com/content/repositories/releases"
    val twitterRepo = "Twitter Repo" at "http://maven.twttr.com"

    val buildSettings = Defaults.defaultSettings ++ gatlingSettings ++ Seq (
      scalaVersion := "2.9.1",
      gatlingVersion := "1.1.1",
      version      := "0.1-SNAPSHOT",
      resolvers ++= Seq(excilysReleaseRepo, twitterRepo))

    lazy val gatling = Project("gatling", file("."), settings = buildSettings)
}