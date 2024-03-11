import speakeasy from 'speakeasy';
import UserRepository from "../repository/user.respository.js";
import registerSchema from "../validations/auth/register.js"
import loginSchema from "../validations/auth/login.js"
import token2FASchema from "../validations/auth/token.2fa.js"
import Jwt from "../utils/jwt.js";
import User2FALogin from '../repository/user.2fa.login.repository.js';
import dotenv from 'dotenv';
import NotFoundError from '../exceptions/not.found.js';
import UnprocessableEntity from '../exceptions/unporcessable.entitiy.js';
import UnauthorizedError from '../exceptions/unauthorized.js';
import BadRequest from '../exceptions/bad.request.js';

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

  async login(req, res, next) {
    try {
      const { error } = await loginSchema.validate(req.body);

      if (error) throw new UnprocessableEntity(error.details[0].message)

      const { username, password } = req.body

      const user = await this.userRepository.findByUsername(username)

      if (!user) throw new UnauthorizedError("Username not found")

      if (user.login_attempts >= 3) {
        const { captcha } = req.body

        if (!captcha) throw new UnprocessableEntity("Captha required")

        const result = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.SECRET_KEY}&response=${captcha}`)
        
        console.log(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.SECRET_KEY}&response=${captcha}`)
        const json = await result.json()
        
        const { success } = json

        if (!success) throw new UnauthorizedError("Invalid captcha")
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
          message: "Password not valid",
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
              status: "OK",
              message: "Input token 2fa",
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
            code: 200,
            status: "OK",
            message: "Input token 2fa",
            data: {
              token: token2fa.uuid
            }
          })
      }

      const { id } = user

      const accessToken = await this.jwt.sign({ id })
      res.status(200)
        .json({
          success: true,
          code: 200,
          status: "OK",
          message: "Login Success",
          data: {
            accessToken
          }
        })
    } catch (error) {
      next(error)
    }
  }

  async register(req, res, next) {
    try {
      const { error } = await registerSchema.validate(req.body);

      if (error) throw new UnprocessableEntity(error.details[0].message)

      const { username, email, password } = req.body

      let user = await this.userRepository.findByEmail(email)
      if (user) throw new BadRequest("Email already taken")

      user = await this.userRepository.findByUsername(username)
      if (user) throw new BadRequest("Username already taken")

      await this.userRepository.create(username, email, password)

      const { id } = await this.userRepository.findByEmail(email)

      return res.status(201)
        .json({
          success: true,
          code: 201,
          status: "Created",
          message: "User Created",
          data: {
            id,
            username,
            email,
          }
        })
    } catch (error) {
      next(error)
    }
  }

  async verifyToken(req, res, next) {
    try {
      const { uuid } = req.params
      const { error } = await token2FASchema.validate(req.body);

      if (error) throw new UnprocessableEntity(error.details[0].message)

      const { token } = req.body

      const user= await this.user2FALogin.findByUuid(uuid)
      
      if(!user) throw new NotFoundError('Token Not Found')
      const { user_id } = user

      const { secret } = await this.userRepository.findById(user_id)
      const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token
      });

      if (!verified) throw new UnauthorizedError("Invalid token provided")

      const accessToken = await this.jwt.sign({
        id: user_id
      })

      await this.user2FALogin.destroy(uuid)

      return res.status(200)
        .json({
          success: true,
          code: 200,
          status: "OK",
          message: "Login Success",
          data: {
            accessToken
          }
        })
    } catch (error) {
      next(error)
    }
  }
}