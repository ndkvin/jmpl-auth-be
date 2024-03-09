import connection from "../database/connection.js";

export default class User2FALogin {
  constructor() {
    this.connection = connection;

    this.update = this.update.bind(this)
    this.create = this.create.bind(this)
    this.findByUserId = this.findByUserId.bind(this)
    this.findByUuid = this.findByUuid.bind(this)
    this.destroy = this.destroy.bind(this)
  }

  async update(id) {
    const [result] = await this.connection.query(
      `UPDATE users SET 2fa = 1 WHERE id = ?`, [id]);
    return result.affectedRows;
  }

  async create(user_id) {
    const [result] = await this.connection.query(
      `INSERT INTO user_2fa_login (user_id) VALUES (?)`, 
      [user_id]);
    return result.affectedRows;
  }

  async findByUserId(user_id) {
    const [results] = await this.connection.query(
      `SELECT BIN_TO_UUID(uuid) as uuid, user_id FROM user_2fa_login where user_id = ?`, 
      [user_id]);
    return results[0]
  }

  async findByUuid(uuid) {
    const [result] = await this.connection.query(
      `SELECT BIN_TO_UUID(uuid) as uuid, user_id FROM user_2fa_login where uuid = UUID_TO_BIN(?)`,
      [uuid]
    );

    return result[0]
  }

  async destroy(uuid) {
    const [result] = await this.connection.query(
      `DELETE FROM user_2fa_login WHERE uuid = UUID_TO_BIN(?)`, 
      [uuid]);
    return result.affectedRows;
  }
}