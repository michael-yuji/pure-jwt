
val catsVersion   = "2.7.0"
val circeVersion  = "0.14.1"
val scala2Version = "2.13.8"

name := "pure-jwt"

version := "0.0.1"

scalaVersion := scala2Version

lazy val sharedSettings = Seq(
  scalacOptions += "-language:higherKinds",
)

lazy val sharedDependencies = Seq("org.typelevel" %% "cats-core" % catsVersion)

lazy val scalatest = project
  .in(file("modules/scalatest"))
  .dependsOn(core, jdkcrypto, circe)
  .settings(
    libraryDependencies ++= Seq(
      "org.scalatest" %% "scalatest" % "3.2.11" % Test
    )
  )

lazy val core = project
  .in(file("modules/core"))
  .settings(sharedSettings)
  .settings(libraryDependencies ++= sharedDependencies)

lazy val jdkcrypto = project
  .in(file("modules/jdkcrypto"))
  .settings(sharedSettings)
  .dependsOn(core)

lazy val circe = project
  .in(file("modules/circe"))
  .settings(sharedSettings)
  .dependsOn(core)
  .settings(
    libraryDependencies ++= sharedDependencies,
    libraryDependencies ++= Seq(
      "io.circe" %% "circe-core" % circeVersion,
      "io.circe" %% "circe-parser" % circeVersion
    )
  )

lazy val jwt = project.in(file("."))
  .aggregate(core, jdkcrypto, circe, scalatest)