import { SQLiteProvider } from './sqlite.js';

class DatabaseManager {
  constructor() {
    this.provider = null;
    this.activeConnections = new Map();
  }

  async getProvider() {
    if (!this.provider) {
      this.provider = new SQLiteProvider();
      await this.provider.initialize();
    }
    return this.provider;
  }

  async getDatabase(dbType, dbName, connectionString = null) {
    const provider = await this.getProvider();
    const connectionKey = `${dbName}_${connectionString || 'default'}`;

    if (!this.activeConnections.has(connectionKey)) {
      const database = await provider.getDatabase(dbName, connectionString);
      this.activeConnections.set(connectionKey, { provider, database });
    }

    return this.activeConnections.get(connectionKey);
  }

  async findUser(dbType, dbName, connectionString, query, projection = {}) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.findUser(database, query, projection);
  }

  async insertUser(dbType, dbName, connectionString, userData) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.insertUser(database, userData);
  }

  async updateUser(dbType, dbName, connectionString, query, update) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.updateUser(database, query, update);
  }

  async findAuth(dbType, dbName, connectionString, query) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.findAuth(database, query);
  }

  async insertAuth(dbType, dbName, connectionString, authData) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.insertAuth(database, authData);
  }

  async executeQuery(dbType, dbName, connectionString, queryObject) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.execute(database, queryObject);
  }

  // Profile cache methods
  async getCachedProfile(dbType, dbName, connectionString, username) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.getCachedProfile(database, username);
  }

  async setCachedProfile(dbType, dbName, connectionString, username, data) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.setCachedProfile(database, username, data);
  }

  async cleanExpiredProfiles(dbType, dbName, connectionString, maxAgeMs) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.cleanExpiredProfiles(database, maxAgeMs);
  }

  async clearAllProfiles(dbType, dbName, connectionString) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.clearAllProfiles(database);
  }

  // Image cache methods
  async getCachedImage(dbType, dbName, connectionString, username) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.getCachedImage(database, username);
  }

  async setCachedImage(dbType, dbName, connectionString, username, imageBuffer) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.setCachedImage(database, username, imageBuffer);
  }

  async cleanExpiredImages(dbType, dbName, connectionString, maxAgeMs) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.cleanExpiredImages(database, maxAgeMs);
  }

  // Profile images methods (avatar/banner)
  async getProfileImage(dbType, dbName, connectionString, id) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.getProfileImage(database, id);
  }

  async setProfileImage(dbType, dbName, connectionString, id, imageBuffer, contentType) {
    const { provider, database } = await this.getDatabase(dbType, dbName, connectionString);
    return await provider.setProfileImage(database, id, imageBuffer, contentType);
  }

  async closeAll() {
    if (this.provider) {
      await this.provider.closeAll();
    }
    this.provider = null;
    this.activeConnections.clear();
  }
}

export const databaseManager = new DatabaseManager();
