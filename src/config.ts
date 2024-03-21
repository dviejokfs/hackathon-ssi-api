import { Entities } from '@veramo/data-store';
import { DataSource } from "typeorm";
import * as models from "./models";
import { KeyType, KEY_TYPES } from "@blockchain-lab-um/did-provider-key"
import { DIDStore, KeyStore, PrivateKeyStore, migrations } from '@veramo/data-store';
interface Config {
    kmsSecretKey: any;
    // key
    privateKey: string;
    did?: string;

    agentLabel: string;

    keyType: KeyType;

    externalUri: string;
    postgresHost?: string;
    postgresPort?: number;
    postgresUser?: string;
    postgresPassword?: string;
    postgresDatabase?: string;
    postgresSSL?: boolean;

    sqlitePath: string;
    databaseType: "postgres" | "sqlite";

}

export const config: Config = {
    keyType: process.env.KEY_TYPE as KeyType,
    databaseType: process.env.DATABASE_TYPE as any || "postgres",
    kmsSecretKey: process.env.KMS_SECRET_KEY,
    privateKey: process.env.PRIVATE_KEY,
    externalUri: process.env.EXTERNAL_URI,
    agentLabel: process.env.AGENT_LABEL,
    postgresHost: process.env.POSTGRES_HOST,
    postgresPort: process.env.POSTGRES_PORT ? Number(process.env.POSTGRES_PORT) : 5432,
    postgresUser: process.env.POSTGRES_USER,
    postgresPassword: process.env.POSTGRES_PASSWORD,
    postgresDatabase: process.env.POSTGRES_DATABASE,
    postgresSSL: process.env.POSTGRES_SSL ? Boolean(process.env.POSTGRES_SSL) : false,
    sqlitePath: process.env.SQLITE_PATH || "./sqlite.db",
}
function getVeramoDataSource() {
    switch (config.databaseType) {
        case "postgres":
            return new DataSource({
                type: 'postgres',
                host: config.postgresHost,
                port: config.postgresPort,
                username: config.postgresUser,
                password: config.postgresPassword,
                database: config.postgresDatabase,
                migrations,
                ssl: config.postgresSSL ? {
                    rejectUnauthorized: false
                } : false,
                migrationsRun: true,
                entities: [
                    ...Entities
                ],
            })
        case "sqlite":
            return new DataSource({
                type: 'sqlite',
                database: config.sqlitePath,
                migrationsRun: true,
                migrations,
                entities: [
                    ...Entities
                ],
            })
        default:
            throw new Error(`DATABASE_TYPE must be one of ${databasesSupported.join(",")}`)
    }
}
function getAppDataSource() {
    switch (config.databaseType) {
        case "postgres":
            return new DataSource({
                type: 'postgres',
                host: config.postgresHost,
                port: config.postgresPort,
                username: config.postgresUser,
                password: config.postgresPassword,
                database: config.postgresDatabase,
                ssl: config.postgresSSL ? {
                    rejectUnauthorized: false
                } : false,
                synchronize: true,
                entities: [
                    models.StateItem,
                ],
            })
        case "sqlite":
            return new DataSource({
                type: 'sqlite',
                database: config.sqlitePath,
                synchronize: true,
                entities: [
                    models.StateItem,
                ],
            })
        default:
            throw new Error(`DATABASE_TYPE must be one of ${databasesSupported.join(",")}`)
    }
}
export const veramoDataSource = getVeramoDataSource()
export const dataSource = getAppDataSource()

const databasesSupported = [
    "postgres",
    "sqlite"

]
function validatePostgresConfig() {
    if (!config.keyType) {
        throw new Error('KEY_TYPE must be set')
    }
    if (!KEY_TYPES.includes(config.keyType)) {
        throw new Error(`KEY_TYPE must be one of ${KEY_TYPES.join(",")}`)
    }
    if (!config.postgresUser) {
        throw new Error('POSTGRES_USER must be set')
    }
    if (!config.postgresPassword) {
        throw new Error('POSTGRES_PASSWORD must be set')
    }
    if (!config.postgresHost) {
        throw new Error('POSTGRES_HOST must be set')
    }
    if (!config.postgresPort) {
        throw new Error('POSTGRES_PORT must be set')
    }
    if (!config.postgresDatabase) {
        throw new Error('POSTGRES_DATABASE must be set')
    }
}

function validateSqliteConfig() {
    if (!config.sqlitePath) {
        throw new Error('SQLITE_PATH must be set')
    }
}

export function validateConfig() {
    if (!config.kmsSecretKey) {
        throw new Error('KMS_SECRET_KEY must be set')
    }
    if (!config.privateKey) {
        throw new Error('PRIVATE_KEY must be set')
    }
    if (!config.externalUri) {
        throw new Error('EXTERNAL_URI must be set')
    }
    if (!databasesSupported.includes(config.databaseType)) {
        throw new Error(`DATABASE_TYPE must be one of ${databasesSupported.join(",")}`)
    }
    switch (config.databaseType) {
        case "postgres":
            validatePostgresConfig()
            break;
        case "sqlite":
            validateSqliteConfig()
            break;
    }
    if (!config.agentLabel) {
        throw new Error('AGENT_LABEL must be set')
    }
}

