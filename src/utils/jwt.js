import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export default class Jwt {
  async sign(payload) {
    return await jwt.sign(payload, process.env.SECRET_JWT, { expiresIn: '1h' });
  }

  async verify(token) {
    return await jwt.verify(token, process.env.SECRET_JWT);
  }
}