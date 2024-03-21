// Core interfaces
import {
    ICredentialIssuer,
    ICredentialPlugin,
    ICredentialVerifier,
    IDIDManager,
    IDataStore,
    IDataStoreORM,
    IKeyManager,
    IResolver,
    createAgent,
} from '@veramo/core';

import { KeyDIDProvider, getDidKeyResolver } from '@blockchain-lab-um/did-provider-key';
import { OID4VCIIssuer } from "@sphereon/ssi-sdk.oid4vci-issuer";
import { OID4VCIStore } from '@sphereon/ssi-sdk.oid4vci-issuer-store';
import { DIDManager } from '@veramo/did-manager';

import { KeyManager } from '@veramo/key-manager';

import { CredentialIssuerEIP712 } from '@veramo/credential-eip712';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local';

import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import { getResolver as webDidResolver } from 'web-did-resolver';

import { DIDStore, KeyStore, PrivateKeyStore, migrations } from '@veramo/data-store';

import { config, veramoDataSource } from './config';




// This will be the secret key for the KMS
const KMS_SECRET_KEY = config.kmsSecretKey;


const resolver = new Resolver({
    ...getDidKeyResolver(),
    ...webDidResolver(),
})

export const agent = createAgent<
    IDIDManager & IKeyManager & IDataStore & IDataStoreORM & IResolver & ICredentialPlugin & ICredentialIssuer &
    ICredentialVerifier & OID4VCIIssuer & OID4VCIStore
>({
    plugins: [
        new KeyManager({
            store: new KeyStore(veramoDataSource),
            kms: {
                local: new KeyManagementSystem(new PrivateKeyStore(veramoDataSource, new SecretBox(KMS_SECRET_KEY))),
            },
        }),
        new DIDManager({
            store: new DIDStore(veramoDataSource),
            defaultProvider: 'did:ethr:goerli',
            providers: {
                'did:key': new KeyDIDProvider({
                    defaultKms: 'local',
                }),
            },
        }),
        new DIDResolverPlugin({
            resolver
        }),
        new CredentialPlugin(),
        new CredentialIssuerEIP712(),
        new OID4VCIStore({}),
        new OID4VCIIssuer({
            resolveOpts: {
                resolver
            }
        }),
    ],
})
