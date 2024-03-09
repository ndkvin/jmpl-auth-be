import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import UserRepository from '../repository/user.respository.js';
import Jwt from '../utils/jwt.js';
import UnauthorizedError from '../exceptions/unauthorized.js';
import BadRequest from '../exceptions/bad.request.js';

export default class TwoFAController {
  constructor() {
    this.userRepository = new UserRepository()
    this.jwt = new Jwt()
    this.generate = this.generate.bind(this);
    this.verify = this.verify.bind(this);
  }

  async generate(req, res, next) {
    try {
      const user = await this.userRepository.findById(req.user.id)

      if (user['2fa']) throw new BadRequest("You already enable 2fa")

      const secret = speakeasy.generateSecret({
        name: "JMPL Auth"
      });

      const image = await qrcode.toDataURL(secret.otpauth_url)

      await this.userRepository.updateSecret(req.user.id, secret.base32);

      return res.json({
        success: true,
        code: 200,
        status: "OK",
        data: {
          image: image.split(';base64,').pop()
        },
      });
    } catch (error) {
      next(error)
    }
  }

  async verify(req, res, next) {
    try {
      const { id } = req.user;
      const user = await this.userRepository.findById(id);

      const userToken = req.body.token;

      const verified = speakeasy.totp.verify({
        secret: user.secret,
        encoding: 'base32',
        token: userToken
      });

      if (!verified) throw new UnauthorizedError("Invalid token provided")

      await this.userRepository.update2FA(req.user.id)

      return res.status(200)
        .json({
          success: true,
          code: 200,
          message: "2FA Successfully Enabled"
        })
    } catch (error) {
      next(error)
    }
  }
}
