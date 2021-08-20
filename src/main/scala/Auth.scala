package lila.ws

import com.typesafe.scalalogging.Logger
import reactivemongo.api.bson._

import scala.concurrent.{ExecutionContext, Future}
import util.RequestHeader

final class Auth(mongo: Mongo, seenAt: SeenAtUpdate)(implicit executionContext: ExecutionContext) {

  import Auth._
  private val logger = Logger(getClass)

  def apply(req: RequestHeader): Future[Option[User]] = getUser(req).map { user =>
    logger.info(s"Authentication from request: $user")
    user
  }

  private def getUser(req: RequestHeader): Future[Option[User]] =
    if (req.flag contains Flag.api) {
      logger.info(s"Session id not extracted. Request flag: ${req.flag}")
      Future successful None
    }
    else
      sessionIdFromReq(req) map { sid =>
        logger.info(s"Session id: $sid")
        sid
      } match {
        case Some(sid) if sid startsWith appealPrefix => Future successful None
        case Some(sid) =>
          mongo.security {
            _.find(
              BSONDocument("_id" -> sid, "up" -> true),
              Some(BSONDocument("_id" -> false, "user" -> true))
            ).one[BSONDocument]
          } map {
            _ flatMap {
              _.getAsOpt[User.ID]("user") map User.apply
            }
          } map {
            _ map { user =>
              Impersonations.get(user.id) match {
                case None =>
                  seenAt(user)
                  user
                case Some(impersonatedId) => User(impersonatedId)
              }
            }
          }
        case None => Future successful None
      }
}

object Auth {
  private val cookieName     = "lila2"
  private val sessionIdKey   = "sessionId"
  private val sessionIdRegex = s"""$sessionIdKey=(\\w+)""".r.unanchored
  private val sidKey         = "sid"
  private val sidRegex       = s"""$sidKey=(\\w+)""".r.unanchored
  private val appealPrefix   = "appeal:"
  private val logger = Logger(getClass)

  def sessionIdFromReq(req: RequestHeader): Option[String] = {
    logger.info(s"Extracting sessionId from request: cookies - ${req.cookie(cookieName)}, query - ${req.queryParameter(sessionIdKey)}")
    req cookie cookieName flatMap {
      case sessionIdRegex(id) => Some(id)
      case _                  => None
    } orElse
      req.queryParameter(sessionIdKey)
  }

  def sidFromReq(req: RequestHeader): Option[String] =
    req cookie cookieName flatMap {
      case sidRegex(id) => Some(id)
      case _            => None
    }
}
