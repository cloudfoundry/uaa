import collection.Seq
import sbt._
import Keys._


object GatlingPlugin {

  val gatling = TaskKey[Unit]("gatling")

  //val gatlingRunner = SettingKey[Gatling]("gatling-runner")
  val gatlingResultsDirectory = SettingKey[String]("gatling-results-directory")
  val gatlingDataDirectory = SettingKey[String]("gatling-data-directory")
  val gatlingConfigFile = SettingKey[String]("gatling-config-file")

  lazy val baseGatlingSettings: Seq[Project.Setting[_]] = Seq(
    fullClasspath in gatling <<= fullClasspath or (fullClasspath in Runtime).identity,
    gatlingResultsDirectory <<= target(_.getAbsolutePath + "/gatling-results"),
    gatlingDataDirectory <<= (resourceDirectory in Compile).apply(_.getAbsolutePath),
    gatlingConfigFile <<= (resourceDirectory in Compile).apply(_.getAbsolutePath + "/gatling.conf"),
//    gatlingRunner <<= (gatlingResultsDirectory, gatlingDataDirectory, gatlingConfigFile, classDirectory in Compile).apply ({
//      (results, data, config, classes) =>
//        new Gatling(Options(
//          resultsFolder = Some(results),
//          configFileName = Some(config),
//          dataFolder = Some(data),
//          simulationBinariesFolder = Some(classes.absolutePath)))
//    }),
/*
    gatling <<= (gatlingRunner, taskTemporaryDirectory, scalaInstance, target, resourceDirectory in Compile, fullClasspath in gatling, classDirectory in Compile) map { (gat, temp, si, tgt, rd, cp, cd) =>
      val oldLoader = Thread.currentThread.getContextClassLoader
      val loader = ClasspathUtilities.makeLoader(Build.data(cp), Gatling.getClass.getClassLoader, si)
      println("Loader is : " + loader.asInstanceOf[URLClassLoader].getURLs.mkString(","))
      Thread.currentThread.setContextClassLoader(loader)

      println("Context Loader is : " + oldLoader.asInstanceOf[URLClassLoader].getURLs.mkString(","))

      println("Gatling loader is: " +  Gatling.getClass.getClassLoader.asInstanceOf[URLClassLoader].getURLs.mkString(","))

//
      try {
        gat.start
//        new Gatling(Options(resultsFolder = Some((tgt / "gatling-results").getAbsolutePath),
//          dataFolder = Some(rd.absolutePath),
//          configFileName = Some(rd.absolutePath + "/gatling.conf"),
//          simulationBinariesFolder = Some(cd.absolutePath))).start
      }
      finally { Thread.currentThread.setContextClassLoader(oldLoader) }
*/
    gatling <<= (streams, gatlingResultsDirectory, gatlingDataDirectory, gatlingConfigFile, fullClasspath in gatling, classDirectory in Compile, runner in run)
        map { (s, grd, gdd, gcf, cp, cd, runner) => {
        val args = Array("--results-folder", grd,
                        "--data-folder", gdd,
                        "--config-file", gcf,
                        "--simulations-binaries-folder", cd.absolutePath)

        val classpath = Build.data(cp)
//        println("Classpath is : " + classpath)

        toError(runner.run("com.excilys.ebi.gatling.app.Gatling", classpath, args, s.log))
      }
    }
  )
}

object UaaGatlingBuild extends Build {

    val gatlingVersion = "1.1.1-SNAPSHOT"

    val gatlingDeps =  Seq(
        "com.excilys.ebi.gatling" % "gatling-app" % gatlingVersion,
        "com.excilys.ebi.gatling" % "gatling-http" % gatlingVersion,
        "com.excilys.ebi.gatling.highcharts" % "gatling-charts-highcharts" % gatlingVersion
    )

    val mavenLocalRepo = "Local Maven Repository" at "file://" + Path.userHome.absolutePath +"/.m2/repository"

    val buildSettings = Defaults.defaultSettings ++ Seq (
      scalaVersion := "2.9.1",
      version      := "0.1-SNAPSHOT",
      resolvers += mavenLocalRepo,
      libraryDependencies ++= gatlingDeps)

    lazy val gatling = Project("gatling", file("."), settings=buildSettings ++ GatlingPlugin.baseGatlingSettings)
}