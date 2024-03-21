import 'reflect-metadata'
import { ICreateKeyDidOptions } from '@blockchain-lab-um/did-provider-key'
import { getResolver as getEbsiDidResolver } from '@cef-ebsi/key-did-resolver'
import { getUniResolver } from '@sphereon/did-uni-client'
import {
	CNonceState,
	CredentialDataSupplierInput,
	CredentialOfferSession,
	CredentialRequestV1_0_11,
	CredentialSupported,
	CredentialsSupportedDisplay,
	Grant,
	GrantTypes,
	OID4VCICredentialFormat,
	PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
	Jwt as SphereonJWT,
	TokenError,
	TokenErrorResponse,
	URIState,
	determineGrantTypes,
} from '@sphereon/oid4vci-common'
import * as QRCode from 'qrcode'
import { CredentialDataSupplierResult, CredentialSupportedBuilderV1_11, VcIssuerBuilder, assertValidAccessTokenRequest, createAccessTokenResponse } from '@sphereon/oid4vci-issuer'
import { ICreateCredentialOfferURIResponse } from '@sphereon/oid4vci-issuer-server'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { getDidJwkResolver } from '@sphereon/ssi-sdk-ext.did-resolver-jwk'
import { getAccessTokenSignerCallback, getCredentialSignerCallback } from '@sphereon/ssi-sdk.oid4vci-issuer'
import { CredentialFormat } from '@sphereon/ssi-types'
import { IDIDManagerCreateArgs, IIdentifier } from '@veramo/core'
import cors from 'cors'
import { decodeJWT, verifyJWT } from 'did-jwt'
import { DIDDocument, Resolver } from 'did-resolver'
import express from 'express'
import { v4 } from 'uuid'
import { agent } from './agent'
import { config, dataSource } from './config'
import log from './log'
import * as models from './models'
import { PostgresStates } from './postgresStore'

const ebsiDidResolver = getEbsiDidResolver()
const jwkResolver = getDidJwkResolver()
const resolver = new Resolver({
	...jwkResolver,
	...ebsiDidResolver,
	...getUniResolver('lto', { resolveUrl: 'https://uniresolver.test.sphereon.io/1.0/identifiers' }),
	...getUniResolver('factom', { resolveUrl: 'https://uniresolver.test.sphereon.io/1.0/identifiers' }),
})

async function generateQR(text: string) {
	try {
		const url = await QRCode.toBuffer(text)
		return url
	} catch (err) {
		console.error(err)
		return ''
	}
}

async function main() {
	const ISSUER_URI = config.externalUri
	const getVCIssuer = async () => {
		// const issuer = await k8sApi.listNamespacedCustomObject(crdGroup, crdVersion, 'default', crdPlural);
		// const credentials = issuer.body as { items: any[] };
		// log.info("credentials updated", credentials)
		const credentials = [
			{
				spec: {
					types: ['VerifiableCredential', 'CourseCompletion'],
					name: 'CourseCompletion',
					format: 'jwt_vc_json' as OID4VCICredentialFormat,
					display: [
						{
							name: 'Completion of course',
							description: 'Certificate for completing a course',
							locale: 'en-US',
						},
					] as CredentialsSupportedDisplay[],
				},
			},
		]
		const credentialsSupported = credentials.map<CredentialSupported>(
			(schema: {
				spec: {
					types: string[]
					name: string
					format: OID4VCICredentialFormat
					display: CredentialsSupportedDisplay[]
				}
			}) => {
				const credSupported = new CredentialSupportedBuilderV1_11()
					.withCryptographicSuitesSupported('ES256K')
					.withCryptographicBindingMethod('did')
					.withFormat(schema.spec.format)
					.withTypes(schema.spec.types)
					.withId(schema.spec.types.join(':'))
					.withCredentialSupportedDisplay(schema.spec.display)
					.build()
				return credSupported
			}
		)
		const tenantName = config.agentLabel
		const credentialSignerCallback = getCredentialSignerCallback(
			{
				identifierOpts: {
					identifier: issuerDid.did,
				},
			},
			{
				agent: agent as any,
			}
		)

		let vcIssuer = new VcIssuerBuilder<DIDDocument>()
			.withCredentialEndpoint(`${ISSUER_URI}/credential`)
			.withCredentialIssuer(`${ISSUER_URI}`)
			.withIssuerDisplay({
				name: tenantName,
				locale: 'en-US',
			})
			.withCredentialsSupported(credentialsSupported)
			.withCredentialOfferStateManager(stateManager)
			.withCredentialOfferURIStateManager(stateCredUriManager)
			.withCNonceStateManager(nonces)
			.withUserPinRequired(true)
			.withCredentialSignerCallback(credentialSignerCallback)
			.withCredentialDataSupplier((args) => {
                console.log('args', args)
				return Promise.resolve({
					credential: {
						'@context': ['https://www.w3.org/2018/credentials/v1'],
						type: ['VerifiableCredential'],
						expirationDate: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(),
						issuer: issuerDid.did,
						issuanceDate: new Date().toISOString(),
						credentialSubject: {
							...args.credentialDataSupplierInput,
						},
					},
					format: 'jwt_vc_json',
				}) as Promise<CredentialDataSupplierResult>
			})
			.withJWTVerifyCallback(async (args) => {
				try {
					const jwt = (await decodeJWT(args.jwt)) as SphereonJWT
					const kid = args.kid ?? jwt.header.kid
					if (!kid) {
						throw Error('No kid value found')
					}
					if (jwt.payload.iss !== 'sphereon:ssi-wallet') {
						const result = await verifyJWT(args.jwt, {
							resolver: resolver,
						})
						if (!result.verified) {
							log.info('JWT not verified')
							throw new Error('JWT not verified')
						}
					}
					const did = kid.split('#')[0]
					const didResolution = await resolver.resolve(did)
					if (!didResolution || !didResolution.didDocument) {
						throw Error(`Could not resolve did: ${did}, metadata: ${didResolution?.didResolutionMetadata}`)
					}
					const didDocument = didResolution.didDocument
					const alg = jwt.header.alg
					const result = {
						alg,
						kid,
						did,
						didDocument,
						jwt,
					}
					return result
				} catch (e) {
					console.error(e)
					throw e
				}
			})
			.build()
		return vcIssuer
	}
	await dataSource.initialize()
	const PORT = Number(process.env.PORT || 3100)
	const app = express()

	app.use(express.json({}))
	app.use(express.raw({}))
	app.use(
		express.urlencoded({
			extended: true,
		})
	)
	app.use(cors())
	app.use(async (req, res, next) => {
		const { method, url, body, headers } = req
		const message = `Incoming request - ${method} - ${url}`
		log.info(message, {
			message,
			method,
			body,
			headers,
		})
		next()
	})
	app.get('/ping', async (request, response) => {
		response.send('pong')
	})
	app.get('/health', async (request, response) => {
		response.send('healthy')
	})

	const itemRepository = dataSource.getRepository(models.StateItem)

	const expiresIn = process.env.EXPIRES_IN ? parseInt(process.env.EXPIRES_IN) : 90
	const stateManager = new PostgresStates<CredentialOfferSession>(itemRepository)
	const stateCredUriManager = new PostgresStates<URIState>(itemRepository)
	const nonces = new PostgresStates<CNonceState>(itemRepository)

	let issuerDid: IIdentifier | null = null
	const didCreateArgs: IDIDManagerCreateArgs = {
		provider: 'did:key',
		alias: 'issuer',
		options: {
			keyType: config.keyType,
			privateKeyHex: config.privateKey,
		} as ICreateKeyDidOptions,
	}
	try {
		const id = await agent.didManagerGetByAlias({
			alias: didCreateArgs.alias!,
			provider: didCreateArgs.provider,
		})
		await agent.didManagerDelete({
			did: id.did,
		})
		issuerDid = await agent.didManagerCreate(didCreateArgs)
	} catch (e) {
		log.info('error', e)
		// did doesn't exists
		issuerDid = await agent.didManagerCreate(didCreateArgs)
	}
	log.info('issuerDid', issuerDid)

	let vcIssuer = await getVCIssuer()

	const accessTokenSignerCallback = getAccessTokenSignerCallback(
		{
			didOpts: {
				identifierOpts: {
					identifier: issuerDid.did,
					kid: issuerDid.keys[0].kid,
				},
			},
		},
		{ agent: agent as any }
	)

	app.post('/credential', async (request, response) => {
		try {
			const credentialRequest = request.body as CredentialRequestV1_0_11

			const credentialResponse = await vcIssuer.issueCredential({
				credentialRequest: credentialRequest,
				tokenExpiresIn: 180000,
				cNonceExpiresIn: 180000,
			})
			return response.send(credentialResponse)
		} catch (e) {
			return sendErrorResponse(
				response,
				500,
				{
					error: 'invalid_request',
					error_description: (e as Error).message,
				},
				e
			)
		}
	})

	app.post('/token', async (request, response) => {
		try {
			const body = request.body
			log.info('token request', body)
			const preAuthorizedCodeExpirationDuration = 300000
			await assertValidAccessTokenRequest(body, {
				expirationDuration: preAuthorizedCodeExpirationDuration,
				credentialOfferSessions: vcIssuer.credentialOfferSessions,
			})
			response.set({
				'Cache-Control': 'no-store',
				Pragma: 'no-cache',
			})
			if (body.grant_type !== GrantTypes.PRE_AUTHORIZED_CODE) {
				// Yes this is redundant, only here to remind us that we need to implement the auth flow as well
				throw new Error(
					JSON.stringify({
						error: TokenErrorResponse.invalid_request,
						error_description: PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
					})
				)
			}
			const interval = 300000
			const tokenExpiresIn = 300
			const accessTokenIssuer = vcIssuer.issuerMetadata.credential_issuer
			const cNonceExpiresIn = vcIssuer.cNonceExpiresIn
			const responseBody = await createAccessTokenResponse(body, {
				credentialOfferSessions: vcIssuer.credentialOfferSessions,
				accessTokenIssuer,
				cNonces: vcIssuer.cNonces,
				cNonce: v4(),
				accessTokenSignerCallback,
				cNonceExpiresIn,
				interval,
				tokenExpiresIn,
			})
			return response.send(responseBody)
		} catch (error) {
			if (error instanceof TokenError) {
				throw new Error(
					JSON.stringify({
						error: error.responseError,
						error_description: error.getDescription(),
					})
				)
			} else {
				throw new Error(
					JSON.stringify({
						error: TokenErrorResponse.invalid_request,
						error_description: (error as Error).message,
					})
				)
			}
		}
	})

	// openid-configuration endpoint
	app.get('/.well-known/openid-configuration', async (request, response) => {
		const serverUrl = `${config.externalUri}`
		response.send({
			redirect_uris: [`${serverUrl}/direct_post`],
			issuer: serverUrl,
			authorization_endpoint: `${serverUrl}/authorize`,
			token_endpoint: `${serverUrl}/token`,
			jwks_uri: `${serverUrl}/jwks`,
			scopes_supported: ['openid'],
			response_types_supported: ['vp_token', 'id_token'],
			response_modes_supported: ['query'],
			grant_types_supported: ['authorization_code'],
			subject_types_supported: ['public'],
			id_token_signing_alg_values_supported: ['ES256'],
			request_object_signing_alg_values_supported: ['ES256'],
			request_parameter_supported: true,
			request_uri_parameter_supported: true,
			token_endpoint_auth_methods_supported: ['private_key_jwt'],
			request_authentication_methods_supported: {
				authorization_endpoint: ['request_object'],
			},
			vp_formats_supported: {
				jwt_vp: {
					alg_values_supported: ['ES256'],
				},
				jwt_vc: {
					alg_values_supported: ['ES256'],
				},
			},
			subject_syntax_types_supported: ['did:key'],
			subject_syntax_types_discriminations: ['did:key:jwk_jcs-pub', 'did:ebsi:v1'],
			subject_trust_frameworks_supported: ['ebsi'],
			id_token_types_supported: ['subject_signed_id_token', 'attester_signed_id_token'],
		})
	})

	app.get('/.well-known/openid-credential-issuer', async (request, response) => {
		try {
			response.send(vcIssuer.issuerMetadata)
		} catch (e) {
			sendErrorResponse(
				response,
				500,
				{
					error: 'invalid_request',
					error_description: (e as Error).message,
				},
				e
			)
		}
	})
	app.get('/credential-offers/:id/qr', async (req, res) => {
		try {
			const { id } = req.params
			const fullUrl = `${ISSUER_URI}/credential-offers/${id}`
			const uriResponse = await vcIssuer!.uris!.get(fullUrl)
			if (!uriResponse) {
				log.info('uris', vcIssuer.uris)
				return sendErrorResponse(res, 404, {
					error: 'invalid_request',
					error_description: `URL ${fullUrl} not found`,
				})
			}
			const session = await vcIssuer.credentialOfferSessions.get(uriResponse.preAuthorizedCode as string)
			if (!session || !session.credentialOffer) {
				return sendErrorResponse(res, 404, {
					error: 'invalid_request',
					error_description: `Credential offer ${id} not found`,
				})
			}
			console.log('fullUrl', fullUrl)
			const qr = await generateQR(`openid-credential-offer://?credential_offer_uri=${fullUrl}`)
			// return qr as png image, is a buffer
			res.writeHead(200, { 'Content-Type': 'image/png' })
			return res.end(qr, 'binary')
		} catch (e) {
			return sendErrorResponse(
				res,
				500,
				{
					error: 'invalid_request',
					error_description: (e as Error).message,
				},
				e
			)
		}
	})
	// get credential offer endpoint
	app.get('/credential-offers/:id', async (req, res) => {
		try {
			const { id } = req.params
			const fullUrl = `${ISSUER_URI}${req.url}`
			const uriResponse = await vcIssuer.uris.get(fullUrl)
			if (!uriResponse) {
				return sendErrorResponse(res, 404, {
					error: 'invalid_request',
					error_description: `URL ${fullUrl} not found`,
				})
			}
			const session = await vcIssuer.credentialOfferSessions.get(uriResponse.preAuthorizedCode)
			if (!session || !session.credentialOffer) {
				return sendErrorResponse(res, 404, {
					error: 'invalid_request',
					error_description: `Credential offer ${id} not found`,
				})
			}
			return res.send(JSON.stringify(session.credentialOffer.credential_offer))
		} catch (e) {
			return sendErrorResponse(
				res,
				500,
				{
					error: 'invalid_request',
					error_description: (e as Error).message,
				},
				e
			)
		}
	})

	// create credential offer endpoint
	app.post('/credential-offers', async (request, response) => {
		try {
			const grantTypes = determineGrantTypes(request.body)
			if (grantTypes.length === 0) {
				throw new Error(JSON.stringify({ error: TokenErrorResponse.invalid_grant, error_description: 'No grant type supplied' }))
			}
			const grants = request.body.grants as Grant
			const credentials = request.body.credentials as (string | CredentialFormat)[]
			const credentialDataSupplierInput = request.body.credentialsToIssue as {
				type: string
				data: CredentialDataSupplierInput
			}[]
			if (!credentialDataSupplierInput || credentialDataSupplierInput.length === 0) {
				throw new Error(JSON.stringify({ error: TokenErrorResponse.invalid_request, error_description: 'No credentials to issue supplied' }))
			}
			const credOfferId = v4()
			const result = await vcIssuer.createCredentialOfferURI({
				...request.body,
				grants,
				credentials,
				credentialDefinition: {},
				credentialDataSupplierInput: credentialDataSupplierInput[0].data,
				credentialOfferUri: `${ISSUER_URI}/credential-offers/${credOfferId}`,
			})
			const resultResponse: ICreateCredentialOfferURIResponse = result
			if ('session' in resultResponse) {
				// eslint-disable-next-line @typescript-eslint/ban-ts-comment
				// @ts-ignore
				delete resultResponse.session
			}
			return response.send({
				...resultResponse,
				qrUri: `${ISSUER_URI}/credential-offers/${credOfferId}/qr`,
			})
		} catch (e) {
			console.error(e)
			return sendErrorResponse(
				response,
				500,
				{
					error: TokenErrorResponse.invalid_request,
					error_description: (e as Error).message,
				},
				e
			)
		}
	})

	function errorHandler(err, req, res: express.Response, next) {
		log.info('errorHandler', err)
		res.status(500)
		res.send({ error: err })
	}
	app.use(errorHandler)
	app.listen(PORT, () => {
		log.info(`Agent app listening on port ${PORT}!`)
	})
}

void main()
