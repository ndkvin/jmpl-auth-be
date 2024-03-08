import bcrypt from 'bcrypt';

export default class Bcrypt {
  async hash(password) {
    return await bcrypt.hash(password, 10);
  }

  async compare(password, hash) {
    return await bcrypt.compare(password, hash);
  }
}