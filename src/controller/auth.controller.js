import speakeasy from 'speakeasy';
import UserRepository from "../repository/user.respository.js";
import registerSchema from "../validations/auth/register.js"
import loginSchema from "../validations/auth/login.js"
import token2FASchema from "../validations/auth/token.2fa.js"
import Jwt from "../utils/jwt.js";
import User2FALogin from '../repository/user.2fa.login.repository.js';
import dotenv from 'dotenv';
dotenv.config();

export default class AuthController {
  constructor() {
    this.userRepository = new UserRepository();
    this.user2FALogin = new User2FALogin();
    this.jwt = new Jwt();

    this.register = this.register.bind(this)
    this.login = this.login.bind(this)
    this.verifyToken = this.verifyToken.bind(this)
  }

  async login(req, res) {
    try {
      const { error } = await loginSchema.validate(req.body);

      if (error) {
        return res.status(422)
          .json({
            success: false,
            code: 422,
            status: "Unprocessable Entity",
            errors: error.details[0].message
          })
      }

      const { username, password } = req.body

      const user = await this.userRepository.findByUsername(username)

      if (!user) {
        return res.status(401)
          .json({
            success: false,
            code: 401,
            status: "Unauthorized",
            errors: "Invalid email or password"
          })
      }

      if (user.login_attempts >= 3) {
        const { captcha } = req.body

        const result = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.CLIENT_KEY}&response=${captcha}`)
        const json = await result.json()
        const { success } = json

        if (!success) {
          return res.status(401)
            .json({
              success: false,
              code: 401,
              status: "Unauthorized",
              errors: "Invalid captcha"
            })
        }

        if (!captcha) {
          return res.status(401)
            .json({
              success: false,
              code: 401,
              status: "Unauthorized",
              errors: "Please input the captcha to continue."
            })
        }
      }

      const isPasswordValid = await this.userRepository.comparePassword(password, user.password)

      if (!isPasswordValid) {
        user.login_attempts += 1;
        await this.userRepository.updateLoginCount(user.id, user.login_attempts);
        const attemptsRemaining = user.login_attempts >= 3 ? 0 : 3 - user.login_attempts;

        return res.status(401).json({
          success: false,
          code: 401,
          status: "Unauthorized",
          errors: "Invalid email or password",
          attempts_remaining: attemptsRemaining
        });
      }

      await this.userRepository.updateLoginCount(user.id, 0)

      if (user['2fa']) {
        let token2fa = await this.user2FALogin.findByUserId(user.id)

        if (token2fa) {
          return res.status(200)
            .json({
              success: true,
              code: 200,
              status: "token login",
              data: {
                token: token2fa.uuid
              }
            })
        }

        await this.user2FALogin.create(user.id)

        token2fa = await this.user2FALogin.findByUserId(user.id)

        return res.status(200)
          .json({
            success: true,
            code: 201,
            status: "User created",
            data: {
              token: token2fa.uuid
            }
          })
      }

      const { id } = user

      const accessTtoken = await this.jwt.sign({ id })
      res.status(200)
        .json({
          success: true,
          code: 200,
          status: "OK",
          data: {
            accessTtoken
          }
        })
    } catch (error) {
      console.error(error)

      return res.status(500)
        .json({
          success: false,
          code: 500,
          status: "Internal Server Error"
        })
    }
  }

  async register(req, res) {
    try {
      const { error } = await registerSchema.validate(req.body);

      if (error) {
        return res.status(422)
          .json({
            success: false,
            code: 422,
            status: "Unprocessable Entity",
            errors: error.details[0].message
          })
      }

      const { username, email, password } = req.body

      let user = await this.userRepository.findByEmail(email)

      if (user) {
        return res.status(400)
          .json({
            success: false,
            code: 400,
            status: "Bad Request",
            errors: "email already taken"
          })
      }

      user = await this.userRepository.findByUsername(username)

      if (user) {
        return res.status(400)
          .json({
            success: false,
            code: 400,
            status: "Bad Request",
            errors: "Username already taken"
          })
      }

      await this.userRepository.create(username, email, password)

      user = await this.userRepository.findByEmail(email)

      const { id } = user

      return res.status(201)
        .json({
          success: true,
          code: 201,
          status: "User created",
          data: {
            id,
            username,
            email,
          }
        })
    } catch (error) {
      console.error(error)

      return res.status(500)
        .json({
          success: false,
          code: 500,
          status: "Internal Server Error"
        })

    }
  }

  async verifyToken(req, res) {
    try {
      const { uuid } = req.params
      const { error } = await token2FASchema.validate(req.body);

      if (error) {
        return res.status(422)
          .json({
            success: false,
            code: 422,
            status: "Unprocessable Entity",
            errors: error.details[0].message
          })
      }

      const { token } = req.body

      const user = await this.user2FALogin.findByUuid(uuid)

      if (!user) {
        return res.status(404)
          .json({
            success: false,
            code: 404,
            status: "Not Found"
          })
      }

      const { user_id } = user

      const userData = await this.userRepository.findById(user_id)

      const { secret } = userData

      const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token
      });

      if (verified) {
        const accessTtoken = await this.jwt.sign({
          id: user_id
        })

        await this.user2FALogin.destroy(uuid)

        return res.status(200)
          .json({
            success: true,
            code: 200,
            message: "Login Success",
            data: {
              accessTtoken
            }
          })
      }

      return res.status(401).json({
        success: false,
        code: 401,
        status: "Unauthorized",
        errors: "Invalid Token"
      });
    } catch (error) {
      console.error(error)

      return res.status(500)
        .json({
          success: false,
          code: 500,
          status: "Internal Server Error"
        })
    }
  }
}