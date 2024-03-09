import BadRequest from "../exceptions/bad.request.js";
import NotFoundError from "../exceptions/not.found.js";
import UnauthorizedError from "../exceptions/unauthorized.js";
import UnprocessableEntity from "../exceptions/unporcessable.entitiy.js";

export default function errorHandler(err, req, res, rext) {
  if (err instanceof BadRequest) {
    return res.status(400).json({
      success: false,
      code: 400,
      status: "Bad Request",
      message: err.message
    })
  }

  if (err instanceof UnauthorizedError) {
    return res.status(401).json({
      success: false,
      code: 401,
      status: "Unauthorized",
      message: err.message
    })
  }

  if (err instanceof NotFoundError) {
    return res.status(404).json({
      success: false,
      code: 404,
      status: "Not Found",
      message: err.message
    })
  }
  
  if (err instanceof UnprocessableEntity) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "Unprosessable Entity",
      message: err.message
    })
  }

  console.error(err)

  return res.status(500).json({
    success: false,
    code: 500,
    status: "Internal Server Error",
  });
}