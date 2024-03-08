import connection from "../database/connection.js";
import Bcrypt from "../utils/bcrypt.js";

export default class UserRepository {
  constructor() {
    this.connection = connection;
    this.bcyrpt = new Bcrypt();

    this.findByEmail = this.findByEmail.bind(this)
    this.findByUsername = this.findByUsername.bind(this)
    this.create = this.create.bind(this)
    this.comparePassword = this.comparePassword.bind(this)
    this.updateLoginCount = this.updateLoginCount.bind(this)
    this.update2FA = this.update2FA.bind(this)
    this.createToken2FA = this.createToken2FA.bind(this)
    this.findToken2FAByUserId = this.findToken2FAByUserId.bind(this)
    this.findToken2FAByUuid = this.findToken2FAByUuid.bind(this)
    this.destroyToken2FA = this.destroyToken2FA.bind(this)
  }
  async findById(id) {
    const [results] = await this.connection.query(
      `SELECT * FROM users where id = ?`, 
      [id]);
    return results[0]
  }

  async findByEmail(email) {
    const [results] = await this.connection.query(
      `SELECT * FROM users where email = ?`, 
      [email]);
    return results[0]
  }

  async findByUsername(username) {
    const [results] = await this.connection.query(
      `SELECT * FROM users where username = ?`, 
      [username]);
    return results[0]
  }

  async create(username, email, password) {
    password = await this.bcyrpt.hash(password);

    const [result] = await this.connection.query(
      `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, 
      [username, email, password]);
    
    return result.affectedRows;
  }

  async comparePassword(password, hash) {
    return await this.bcyrpt.compare(password, hash);
  }

  async updateLoginCount(id, login_attempts) {
    const [result] = await this.connection.query(
      `UPDATE users SET login_attempts = ? WHERE id = ?`, 
      [login_attempts, id]
    );
    return result.affectedRows;
  }

  async updateSecret(id, secret) {
    const [result] = await this.connection.query(
      `UPDATE users SET secret = ? WHERE id = ?`, [secret, id]);
    return result.affectedRows;
  }

  async update2FA(id) {
    const [result] = await this.connection.query(
      `UPDATE users SET 2fa = 1 WHERE id = ?`, [id]);
    return result.affectedRows;
  }

  async createToken2FA(user_id) {
    const [result] = await this.connection.query(
      `INSERT INTO user_2fa_login (user_id) VALUES (?)`, 
      [user_id]);
    return result.affectedRows;
  }

  async findToken2FAByUserId(user_id) {
    const [results] = await this.connection.query(
      `SELECT BIN_TO_UUID(uuid) as uuid, user_id FROM user_2fa_login where user_id = ?`, 
      [user_id]);
    return results[0]
  }

  async findToken2FAByUuid(uuid) {
    const [result] = await this.connection.query(
      `SELECT BIN_TO_UUID(uuid) as uuid, user_id FROM user_2fa_login where uuid = UUID_TO_BIN(?)`,
      [uuid]
    );

    return result[0]
  }

  async destroyToken2FA(uuid) {
    const [result] = await this.connection.query(
      `DELETE FROM user_2fa_login WHERE uuid = UUID_TO_BIN(?)`, 
      [uuid]);
    return result.affectedRows;
  }
}