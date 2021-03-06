package org.constellation.util

import akka.http.scaladsl.coding.Gzip
import akka.util.ByteString
import cats.effect.{Async, ContextShift, IO}
import com.softwaremill.sttp._
import com.softwaremill.sttp.json4s._
import com.typesafe.scalalogging.CanLog
import org.constellation.ConstellationExecutionContext
import org.json4s.native.Serialization
import org.json4s.{Formats, native}
import org.slf4j.MDC

import scala.concurrent.duration._
import scala.concurrent.{Await, Future}
import scala.util.{Failure, Success}

case class HostPort(
  host: String,
  port: Int
)

object APIClientBase {

  def apply(
    host: String = "127.0.0.1",
    port: Int,
    authEnabled: Boolean = false,
    authId: String = null,
    authPassword: String = null
  )(
    implicit backend: SttpBackend[Future, Nothing]
  ): APIClientBase =
    new APIClientBase(host, port, authEnabled, authId, authPassword)
}

class APIClientBase(
  host: String = "127.0.0.1",
  port: Int,
  authEnabled: Boolean = false,
  authId: String = null,
  var authPassword: String = null
)(
  implicit backend: SttpBackend[Future, Nothing]
) {

  implicit case object CanLogCorrelationId extends CanLog[HostPort] {
    override def logMessage(originalMsg: String, a: HostPort): String = {
      MDC.put("host", a.host)
      MDC.put("port", a.port.toString)
      originalMsg
    }

    override def afterLog(a: HostPort): Unit = {
      MDC.remove("host")
      MDC.remove("port")
    }
  }

  implicit val hostPortForLogging = HostPort(host, port)

  implicit val serialization = native.Serialization

  val hostName: String = host

  val udpPort: Int = 16180
  val apiPort: Int = port

  def udpAddress: String = hostName + ":" + udpPort

  def baseURI: String = {
    val uri = s"http://$hostName:$apiPort"
    uri
  }

  def setPassword(newPassword: String) = authPassword = newPassword

  def base(suffix: String) = s"$baseURI/$suffix"

  private def baseUri(suffix: String) = s"$baseURI/$suffix"

  implicit class AddBlocking[T](req: Future[T]) {

    def blocking(timeout: Duration = 60.seconds): T =
      Await.result(req, timeout + 100.millis)
  }

  def optHeaders: Map[String, String] = Map()

  def httpWithAuth(suffix: String, params: Map[String, String] = Map.empty, timeout: Duration = 15.seconds)(
    method: Method
  ) = {
    val base = baseUri(suffix)
    val uri = uri"$base?$params"
    val req = sttp.method(method, uri).readTimeout(timeout).headers(optHeaders)
    if (authEnabled) {
      req.auth.basic(authId, authPassword)
    } else req
  }

  def post(suffix: String, b: AnyRef, timeout: Duration = 15.seconds)(
    implicit f: Formats = constellation.constellationFormats
  ): Future[Response[String]] = {
    val ser = Serialization.write(b)
    val gzipped = Gzip.encode(ByteString.fromString(ser)).toArray
    httpWithAuth(suffix, timeout = timeout)(Method.POST)
      .body(gzipped)
      .contentType("application/json")
      .header("Content-Encoding", "gzip")
      .send()
  }

  def put(suffix: String, b: AnyRef, timeout: Duration = 15.seconds)(
    implicit f: Formats = constellation.constellationFormats
  ): Future[Response[String]] = {
    val ser = Serialization.write(b)
    val gzipped = Gzip.encode(ByteString.fromString(ser)).toArray
    httpWithAuth(suffix, timeout = timeout)(Method.PUT)
      .body(gzipped)
      .contentType("application/json")
      .header("Content-Encoding", "gzip")
      .send()
  }

  def putAsync(suffix: String, b: AnyRef, timeout: Duration = 15.seconds)(
    implicit f: Formats = constellation.constellationFormats
  ): IO[Response[String]] =
    IO.fromFuture(IO(put(suffix, b, timeout)))(IO.contextShift(ConstellationExecutionContext.unbounded))

  def postEmpty(suffix: String, timeout: Duration = 15.seconds)(
    implicit f: Formats = constellation.constellationFormats
  ): Response[String] =
    httpWithAuth(suffix, timeout = timeout)(Method.POST).send().blocking()

  def postSync(suffix: String, b: AnyRef, timeout: Duration = 15.seconds)(
    implicit f: Formats = constellation.constellationFormats
  ): Response[String] =
    post(suffix, b, timeout).blocking(timeout)

  def postBlocking[T <: AnyRef](suffix: String, b: AnyRef, timeout: Duration = 15.seconds)(
    implicit m: Manifest[T],
    f: Formats = constellation.constellationFormats
  ): T =
    postNonBlocking(suffix, b, timeout).blocking(timeout)

  def postNonBlocking[T <: AnyRef](
    suffix: String,
    b: AnyRef,
    timeout: Duration = 15.seconds,
    headers: Map[String, String] = Map.empty
  )(
    implicit m: Manifest[T],
    f: Formats = constellation.constellationFormats
  ): Future[T] = {
    val ser = Serialization.write(b)
    val gzipped = Gzip.encode(ByteString.fromString(ser)).toArray
    httpWithAuth(suffix, timeout = timeout)(Method.POST)
      .body(gzipped)
      .contentType("application/json")
      .header("Content-Encoding", "gzip")
      .headers(headers)
      .response(asJson[T])
      .send()
      .map(_.unsafeBody)(ConstellationExecutionContext.unbounded)
  }

  def postNonBlockingArrayByte(
    suffix: String,
    b: AnyRef,
    timeout: Duration = 15.seconds,
    headers: Map[String, String] = Map.empty
  )(
    implicit m: Manifest[Array[Byte]],
    f: Formats = constellation.constellationFormats
  ): Future[Array[Byte]] = {
    val ser = Serialization.write(b)
    val gzipped = Gzip.encode(ByteString.fromString(ser)).toArray
    httpWithAuth(suffix, timeout = timeout)(Method.POST)
      .body(gzipped)
      .contentType("application/json")
      .header("Content-Encoding", "gzip")
      .headers(headers)
      .response(asByteArray)
      .send()
      .map(_.unsafeBody)(ConstellationExecutionContext.unbounded)
  }

  def postNonBlockingUnit(
    suffix: String,
    b: AnyRef,
    timeout: Duration = 15.seconds,
    headers: Map[String, String] = Map.empty
  )(
    implicit f: Formats = constellation.constellationFormats
  ): Future[Response[Unit]] = {
    val ser = Serialization.write(b)
    val gzipped = Gzip.encode(ByteString.fromString(ser)).toArray
    httpWithAuth(suffix, timeout = timeout)(Method.POST)
      .body(gzipped)
      .contentType("application/json")
      .header("Content-Encoding", "gzip")
      .headers(headers)
      .response(ignore)
      .send()
  }

  def postNonBlockingEmpty[T <: AnyRef](
    suffix: String,
    timeout: Duration = 15.seconds
  )(implicit m: Manifest[T], f: Formats = constellation.constellationFormats): Future[T] =
    httpWithAuth(suffix, timeout = timeout)(Method.POST)
      .response(asJson[T])
      .send()
      .map(_.unsafeBody)(ConstellationExecutionContext.unbounded)

  def postNonBlockingEmptyString(
    suffix: String,
    timeout: Duration = 15.seconds
  )(implicit f: Formats = constellation.constellationFormats): Future[Response[String]] =
    httpWithAuth(suffix, timeout = timeout)(Method.POST).send()

  def deleteNonBlockingEmptyString(
    suffix: String,
    timeout: Duration = 15.seconds
  )(implicit f: Formats = constellation.constellationFormats): Future[Response[String]] =
    httpWithAuth(suffix, timeout = timeout)(Method.DELETE).send()

  def getBytes(
    suffix: String,
    queryParams: Map[String, String] = Map(),
    timeout: Duration = 15.seconds
  ): Future[Response[Array[Byte]]] =
    httpWithAuth(suffix, queryParams, timeout)(Method.GET).response(asByteArray).send()

  def getString(
    suffix: String,
    queryParams: Map[String, String] = Map(),
    timeout: Duration = 15.seconds
  ): Future[Response[String]] =
    httpWithAuth(suffix, queryParams, timeout)(Method.GET).send()

  def getStringIO(
    suffix: String,
    queryParams: Map[String, String] = Map(),
    timeout: Duration = 15.seconds
  )(contextToReturn: ContextShift[IO]): IO[Response[String]] =
    contextToReturn.evalOn(ConstellationExecutionContext.unbounded)(Async[IO].async { cb =>
      httpWithAuth(suffix, queryParams, timeout)(Method.GET)
        .send()
        .onComplete {
          case Success(value) => cb(Right(value))
          case Failure(error) => cb(Left(error))
        }(ConstellationExecutionContext.unbounded)
    })

  def getBlocking[T <: AnyRef](
    suffix: String,
    queryParams: Map[String, String] = Map(),
    timeout: Duration = 15.seconds
  )(implicit m: Manifest[T], f: Formats = constellation.constellationFormats): T =
    getNonBlocking[T](suffix, queryParams, timeout).blocking(timeout)

  private[util] def getNonBlocking[T <: AnyRef](
    suffix: String,
    queryParams: Map[String, String] = Map(),
    timeout: Duration = 15.seconds
  )(implicit m: Manifest[T], f: Formats = constellation.constellationFormats): Future[T] =
    httpWithAuth(suffix, queryParams, timeout)(Method.GET)
      .response(asJson[T])
      .send()
      .map(_.unsafeBody)(ConstellationExecutionContext.unbounded)

}
