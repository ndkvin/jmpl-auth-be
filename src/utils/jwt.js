import jwt from 'jsonwebtoken';

export default class Jwt {
  async sign(payload) {
    return await jwt.sign(payload, 'secret', { expiresIn: '1h' });
  }

  async verify(token) {
    return await jwt.verify(token, 'secret');
  }
}