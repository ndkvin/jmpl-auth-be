import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import UserRepository from '../repository/user.respository.js';
import Jwt from '../utils/jwt.js';

export default class TwoFAController {

  constructor() {
    this.userRepository = new UserRepository()
    this.jwt = new Jwt()
    this.generate = this.generate.bind(this);
    this.verify = this.verify.bind(this);
  }

  async generate(req, res) {
    try {
      const user = await this.userRepository.findById(req.user.id)
      //
      if (user['2fa']) {
        return res.status(400).json({
          success: 'false',
          code: 400,
          message: "You already enable 2fa"
        })
      }

      const secret = speakeasy.generateSecret();

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
      console.error(error)

      return res.status(500).json({
        success: false,
        code: 500,
        status: "Internal Server Error",
      });
    }
  }

  async verify(req, res) {
    try {
      const { id } = req.user;
      const user = await this.userRepository.findById(id);

      const userToken = req.body.token;

      const verified = speakeasy.totp.verify({
        secret: user.secret,
        encoding: 'base32',
        token: userToken
      });

      if (verified) {
        const success = await this.userRepository.update2FA(req.user.id)

        if (!success) {
          return res.status(500).json({
            success: false,
            code: 500,
            status: "Internal Server Error",
            errors: "Internal Server Error"
          })
        }
        return res.status(200)
          .json({
            success: true,
            code: 200,
            message: "2FA Successfully Enabled"
          })
      } else {
        return res.status(401).json({
          success: false,
          code: 401,
          status: "Unauthorized",
          errors: "Invalid Token"
        });
      }
    } catch (error) {
      console.error(error)

      return res.status(500).json({
        success: false,
        code: 500,
        status: "Internal Server Error",
        errors: "Internal Server Error"
      });
    }
  }
}
