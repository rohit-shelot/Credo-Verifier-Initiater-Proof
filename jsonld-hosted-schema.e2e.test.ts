import { Buffer } from 'node:buffer'
import { createHmac, randomUUID } from 'node:crypto'
import {
  DidCommAutoAcceptCredential,
  DidCommAutoAcceptProof,
  DidCommCredentialV2Protocol,
  DidCommDifPresentationExchangeProofFormatService,
  DidCommJsonLdCredentialFormatService,
  DidCommModule,
  DidCommProofV2Protocol,
} from '../../didcomm/src'
import { DidCommCredentialState } from '../../didcomm/src/modules/credentials'
import { DidCommProofState } from '../../didcomm/src/modules/proofs'
import type { KeyDidCreateOptions } from '../src'
import {
  Agent,
  asArray,
  CacheModule,
  ClaimFormat,
  defaultDocumentLoader,
  InMemoryLruCache,
  W3cCredentialRecord,
  W3cCredentialsModule,
  w3cDate,
} from '../src'
import { CREDENTIALS_CONTEXT_V1_URL } from '../src/modules/vc/constants'
import type { W3cJsonLdVerifiableCredential } from '../src/modules/vc/linked-data-proofs/models/W3cJsonLdVerifiableCredential'
import type { JsonObject } from '../src/types'
import { getAgentOptions, makeConnection, waitForCredentialRecord } from './helpers'
import { setupSubjectTransports } from './transport'

// The schema server is a separate process that has to be running for this test:
//
//   cd schema-file-server
//   deno run --allow-net --allow-read --allow-env --allow-write server.ts
//
// It serves every published schema from `schemas/<id>.json` and keeps them on disk, so a schema
// also survives between test runs. Note that we talk to the server over `127.0.0.1` and not over
// `localhost`: `IsCredentialJsonLdContext` validates context urls with `class-validator`'s
// `isURL`, which requires a top-level domain and therefore rejects `http://localhost:8000/...`.
const SCHEMA_SERVER_URL = process.env.SCHEMA_SERVER_URL ?? 'http://127.0.0.1:8000'

// The schema server authenticates writes with an HS256 jwt, signed with this base64 encoded secret.
const SCHEMA_SERVER_SECRET =
  process.env.SCHEMA_SERVER_SECRET ?? 'aBbomP4JBcnNn52uoMHAKdhH0zI3IGIq7T7bvtBhgpg='

// The server only accepts alphanumeric schema ids.
const STUDENT_ID_CARD_SCHEMA_ID = 'studentidcard'
const STUDENT_ID_CARD_SCHEMA_URL = `${SCHEMA_SERVER_URL}/schemas/${STUDENT_ID_CARD_SCHEMA_ID}`
const STUDENT_ID_CARD_NAMESPACE = `${STUDENT_ID_CARD_SCHEMA_URL}#`

// The JSON-LD context the issuer authors for its student ID card. The schema is served from
// `STUDENT_ID_CARD_SCHEMA_URL`, so that url is also the base iri of the context.
const STUDENT_ID_CARD_SCHEMA = {
  '@context': [
    { '@version': 1.1 },
    {
      name: STUDENT_ID_CARD_SCHEMA_URL,
      StudentIdCard: `${STUDENT_ID_CARD_NAMESPACE}StudentIdCard`,
      Student: `${STUDENT_ID_CARD_NAMESPACE}Student`,
      studentId: `${STUDENT_ID_CARD_NAMESPACE}studentId`,
      givenName: `${STUDENT_ID_CARD_NAMESPACE}givenName`,
      familyName: `${STUDENT_ID_CARD_NAMESPACE}familyName`,
      university: `${STUDENT_ID_CARD_NAMESPACE}university`,
      enrolmentYear: `${STUDENT_ID_CARD_NAMESPACE}enrolmentYear`,
    },
  ],
} satisfies JsonObject

function createSchemaServerAuthToken() {
  const encode = (value: JsonObject) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const signingInput = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({
    iss: 'CREDEBL-issuer',
    id: randomUUID(),
  })}`

  const signature = createHmac('sha256', Buffer.from(SCHEMA_SERVER_SECRET, 'base64'))
    .update(signingInput)
    .digest('base64url')

  return `${signingInput}.${signature}`
}

/**
 * Publishes the student ID card schema, and returns the document the server serves for it. The
 * server rejects a duplicate id, so an already published schema is simply reused.
 */
async function publishStudentIdCardSchema() {
  const response = await fetch(`${SCHEMA_SERVER_URL}/schemas`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${createSchemaServerAuthToken()}`,
    },
    body: JSON.stringify({
      schemaId: STUDENT_ID_CARD_SCHEMA_ID,
      schema: STUDENT_ID_CARD_SCHEMA,
    }),
  })

  const body = await response.text()

  if (!response.ok && !body.includes('Schema already exists')) {
    throw new Error(
      `Failed to publish schema: ${response.status} ${body || '<empty response>'}`
    )
  }

  const schema = await fetch(STUDENT_ID_CARD_SCHEMA_URL)

  if (!schema.ok) {
    throw new Error(
      `Failed to resolve schema ${STUDENT_ID_CARD_SCHEMA_URL}: ${schema.status}`
    )
  }

  return (await schema.json()) as JsonObject
}

// The agents resolve the hosted schema over http, so they all use the default document loader.
// The holder automatically accepts the proof request, the verifier does not, so that it has to
// verify and accept the presentation itself.
function getModules(
  endpoint: string,
  autoAcceptProofs: DidCommAutoAcceptProof
) {
  return {
    didcomm: new DidCommModule({
      connections: {
        autoAcceptConnections: true,
      },

      endpoints: [endpoint],

      credentials: {
        credentialProtocols: [
          new DidCommCredentialV2Protocol({
            credentialFormats: [
              new DidCommJsonLdCredentialFormatService(),
            ],
          }),
        ],
        autoAcceptCredentials: DidCommAutoAcceptCredential.Always,
      },

      proofs: {
        autoAcceptProofs,

        proofProtocols: [
          new DidCommProofV2Protocol({
            proofFormats: [
              new DidCommDifPresentationExchangeProofFormatService(),
            ],
          }),
        ],
      },
    }),

    w3cCredentials: new W3cCredentialsModule({
      documentLoader: defaultDocumentLoader,
    }),

    cache: new CacheModule({
      cache: new InMemoryLruCache({
        limit: 100,
      }),
    }),
  } as const
}

function createAgent(
  name: string,
  endpoint: string,
  autoAcceptProofs: DidCommAutoAcceptProof
) {
  return new Agent(
    getAgentOptions(
      name,
      {},
      {},
      getModules(endpoint, autoAcceptProofs),
      {
        requireDidcomm: true,
      }
    )
  )
}

async function createEd25519Did(agent: Agent) {
  const { didState } = await agent.dids.create<KeyDidCreateOptions>({
    method: 'key',
    options: {
      createKey: {
        type: {
          kty: 'OKP',
          crv: 'Ed25519',
        },
      },
    },
  })

  return didState.did as string
}

/**
 * Polls the proof record until it reaches `state`. The holder auto accepts, so by the time we start
 * waiting the state event of the verifier may already have been emitted.
 */
async function waitForProofState(
  agent: Agent,
  locator: { id: string } | { threadId: string },
  state: DidCommProofState
) {
  const timeoutMs = 10_000
  const deadline = Date.now() + timeoutMs

  const getRecord = async () => {
    try {
      return 'id' in locator
        ? await agent.didcomm.proofs.getById(locator.id)
        : await agent.didcomm.proofs.getByThreadAndConnectionId(
          locator.threadId
        )
    } catch {
      // The record may not exist yet.
      return undefined
    }
  }

  let proofRecord = await getRecord()

  while (proofRecord?.state !== state) {
    if (Date.now() >= deadline) {
      throw new Error(
        `Proof record did not reach state '${state}' within ${timeoutMs}ms, ` +
        `last state was '${proofRecord?.state}'${proofRecord?.errorMessage
          ? `: ${proofRecord.errorMessage}`
          : ''
        }`
      )
    }

    await new Promise((resolve) => setTimeout(resolve, 50))

    proofRecord = await getRecord()
  }

  return proofRecord
}

describe(
  'JSON-LD W3C credential - student ID card with a schema hosted on a schema server',
  () => {
    let issuerAgent: Agent
    let holderAgent: Agent
    let verifierAgent: Agent

    let issuerHolderConnectionId: string
    let holderVerifierConnectionId: string
    let verifierHolderConnectionId: string

    let issuerDid: string
    let holderDid: string

    beforeAll(async () => {
      issuerAgent = createAgent(
        'student id card issuer',
        'rxjs:issuer',
        DidCommAutoAcceptProof.Always
      )

      holderAgent = createAgent(
        'student id card holder',
        'rxjs:holder',
        DidCommAutoAcceptProof.Always
      )

      verifierAgent = createAgent(
        'student id card verifier',
        'rxjs:verifier',
        DidCommAutoAcceptProof.Never
      )

      setupSubjectTransports([
        issuerAgent,
        holderAgent,
        verifierAgent,
      ])

      await issuerAgent.initialize()
      await holderAgent.initialize()
      await verifierAgent.initialize()

      const [issuerHolderConnection] = await makeConnection(
        issuerAgent,
        holderAgent
      )

      const [
        holderVerifierConnection,
        verifierHolderConnection,
      ] = await makeConnection(
        holderAgent,
        verifierAgent
      )

      issuerHolderConnectionId = issuerHolderConnection.id
      holderVerifierConnectionId = holderVerifierConnection.id
      verifierHolderConnectionId = verifierHolderConnection.id

      issuerDid = await createEd25519Did(issuerAgent)
      holderDid = await createEd25519Did(holderAgent)
    })

    afterAll(async () => {
      await issuerAgent.shutdown()
      await holderAgent.shutdown()
      await verifierAgent.shutdown()
    })

    test(
      'issuer publishes the student ID card schema on the schema server',
      async () => {
        expect(await publishStudentIdCardSchema()).toEqual(
          STUDENT_ID_CARD_SCHEMA
        )

        // Publishing requires a valid jwt.
        const unauthorized = await fetch(
          `${SCHEMA_SERVER_URL}/schemas`,
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              schemaId: 'unauthorized',
              schema: STUDENT_ID_CARD_SCHEMA,
            }),
          }
        )

        expect(unauthorized.status).toBe(401)
      }
    )

    test(
      'issuer issues the student ID card credential to the holder',
      async () => {
        await issuerAgent.didcomm.credentials.offerCredential({
          connectionId: issuerHolderConnectionId,
          protocolVersion: 'v2',

          credentialFormats: {
            jsonld: {
              credential: {
                '@context': [
                  CREDENTIALS_CONTEXT_V1_URL,
                  STUDENT_ID_CARD_SCHEMA_URL,
                ],

                type: [
                  'VerifiableCredential',
                  'StudentIdCard',
                ],

                issuer: issuerDid,

                issuanceDate: w3cDate(),

                credentialSubject: {
                  id: holderDid,
                  type: 'Student',
                  studentId: 'ADT23SOCB0877',
                  givenName: 'Rohit Vijay Shelot',
                  familyName: 'Student',
                  university: 'MIT - ADT University',
                  enrolmentYear: 2023,
                },
              },

              options: {
                proofType: 'Ed25519Signature2018',
                proofPurpose: 'assertionMethod',
              },
            },
          },
        })

        const credentialExchangeRecord =
          await waitForCredentialRecord(holderAgent, {
            state: DidCommCredentialState.Done,
          })

        expect(
          credentialExchangeRecord.credentials
        ).toHaveLength(1)

        const [storedCredential] =
          await holderAgent.w3cCredentials.getAll()

        expect(storedCredential.type).toBe(
          W3cCredentialRecord.type
        )

        expect(storedCredential.getTags()).toMatchObject({
          claimFormat: ClaimFormat.LdpVc,
          issuerId: issuerDid,
          subjectIds: [holderDid],
          contexts: expect.arrayContaining([
            STUDENT_ID_CARD_SCHEMA_URL,
          ]),
          types: expect.arrayContaining([
            'StudentIdCard',
          ]),
        })

        const {
          credentialSubject,
          proof,
        } =
          storedCredential.firstCredential as W3cJsonLdVerifiableCredential

        const subject = asArray(credentialSubject)[0]

        expect(asArray(proof)[0].type).toBe(
          'Ed25519Signature2018'
        )

        expect({
          id: subject.id,
          ...subject.claims,
        }).toMatchObject({
          id: holderDid,
          type: 'Student',
          studentId: 'ADT23SOCB0877',
          givenName: 'Rohit Vijay Shelot',
          familyName: 'Student',
          university: 'MIT - ADT University',
          enrolmentYear: 2023,
        })
      }
    )

    test(
      'verifier requests a proof and the holder presents it',
      async () => {
        // The verifier initiates the proof exchange by requesting
        // the student's ID card.
        const proofRequestRecord =
          await verifierAgent.didcomm.proofs.requestProof({
            connectionId: verifierHolderConnectionId,
            protocolVersion: 'v2',

            proofFormats: {
              presentationExchange: {
                presentationDefinition: {
                  id: 'student-id-card-presentation-definition',

                  input_descriptors: [
                    {
                      id: 'student_id_card_input',

                      schema: [
                        {
                          uri: STUDENT_ID_CARD_SCHEMA_URL,
                        },
                      ],

                      constraints: {
                        fields: [
                          {
                            path: [
                              '$.credentialSubject.studentId',
                            ],
                          },
                        ],
                      },
                    },
                  ],
                },
              },
            },
          })

        // The holder automatically accepts the request and
        // presents the credential it was issued.
        const receivedProofRecord =
          await waitForProofState(
            verifierAgent,
            {
              id: proofRequestRecord.id,
            },
            DidCommProofState.PresentationReceived
          )

        expect(receivedProofRecord.isVerified).toBe(true)

        // The verifier acknowledges the presentation,
        // which completes the exchange.
        const completedProofRecord =
          await verifierAgent.didcomm.proofs.acceptPresentation({
            proofExchangeRecordId: proofRequestRecord.id,
          })

        expect(completedProofRecord.isVerified).toBe(true)

        expect(completedProofRecord.state).toBe(
          DidCommProofState.Done
        )

        expect(
          completedProofRecord.errorMessage
        ).toBeUndefined()

        // The acknowledgement completes the exchange
        // on the holder side as well.
        await waitForProofState(
          holderAgent,
          {
            threadId: proofRequestRecord.threadId,
          },
          DidCommProofState.Done
        )
      }
    )
  }
)
