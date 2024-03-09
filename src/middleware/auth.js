import Jwt from "../utils/jwt.js";

export default class AuthMiddleware {
  constructor() {
    this.jwt = new Jwt();

    this.isLogin = this.isLogin.bind(this);
  }

  async isLogin(req, res, next) {
    const bearerToken = req.headers.authorization;

    if (!bearerToken) {
      return res.status(401).json({
        success: false,
        code: 401,
        status: "Unauthorized",
        errors: "Bearer Token is required"
      });
    }
    const token = bearerToken.split(' ')[1];

    try {
      const payload = await this.jwt.verify(token);
      req.user = payload;
      next();

    } catch (error) {
      return res.status(401).json({
        success: false,
        code: 401,
        status: "Unauthorized",
        errors: "Invalid Token"
      });
    }
  }
}