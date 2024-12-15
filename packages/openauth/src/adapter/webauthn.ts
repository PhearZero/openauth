import { Adapter } from "./adapter.js"
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    PublicKeyCredentialCreationOptionsJSON,
    RegistrationResponseJSON,
    VerifiedRegistrationResponse,
    PublicKeyCredentialRequestOptionsJSON,
    AuthenticationResponseJSON,
    WebAuthnCredential,
    VerifiedAuthenticationResponse
} from "@simplewebauthn/server";

export interface PasskeyConfig {
    registrationOptions: (
        req: Request,
        state: PublicKeyCredentialCreationOptionsJSON,
        form?: FormData,
        error?: PasskeyOptionsError,
    ) => Promise<Response>
    register: (
        req: Request,
        state: VerifiedRegistrationResponse,
        form?: RegistrationResponseJSON,
        error?: PasskeyError,
    ) => Promise<Response>
    loginOptions: (
        req: Request,
        state: PublicKeyCredentialRequestOptionsJSON,
        form?: FormData,
        error?: PasskeyOptionsError,
    ) => Promise<Response>
    login: (
        req: Request,
        state: VerifiedAuthenticationResponse,
        form?: AuthenticationResponseJSON,
        error?: PasskeyError,
    ) => Promise<Response>
}

export type PasskeyError =
    | {
    type: "invalid_passkey"
}

export type PasskeyOptionsError =
 | {
    type: "invalid_options"
}

// TODO: make these configurable
const RP_ID = "localhost"
const RP_NAME = "Passkey Example"
const RP_ORIGIN = `http://${RP_ID}`

export function PasskeyAdapter(config: PasskeyConfig) {
    return {
        type: "passkey",
        init(routes, ctx) {
            // TODO: handle well known asset links for Android with Android app?
            routes.get('/.well-known/asset-links.json', async (c) => {
                return new Response(
                    JSON.stringify({
                        "relation": ["delegate_permission/common.handle_all_urls"],
                        "target": {
                            "namespace": "android_app",
                            "package_name": "com.example.app",
                            "sha256_cert_fingerprints": ["hash_base64"],
                        },
                    }),
                    {
                        headers: {
                            "Content-Type": "application/json",
                        },
                    },
                )
            })
            routes.post("/passkey/register/options", async (c) =>{
                // TODO: better typings with FormData
                const opts = await generateRegistrationOptions({
                    rpID: RP_ID,
                    rpName: RP_NAME,
                    userName: "mfeher",
                    attestationType: "none",
                    excludeCredentials: [], // TODO: fetch existing passkeys
                    authenticatorSelection: {
                        userVerification: "required",
                        residentKey: "preferred"
                    },
                })
                // TODO: persist the generated challenge
                return ctx.forward(c, await config.registrationOptions(c.req.raw, opts))
            })
            routes.post("/passkey/register", async (c) => {
                const valid = await verifyRegistrationResponse({
                    response: await c.req.formData() as RegistrationResponseJSON,
                    expectedChallenge: "challenge", // TODO: fetch the challenge
                    expectedOrigin: RP_ORIGIN, // TODO: Android origin?
                })
                return ctx.forward(c, await config.register(c.req.raw, valid))
            })
            routes.post("/passkey/login/options", async (c) =>{
                const opts = await generateAuthenticationOptions({
                    rpID: RP_ID,
                    allowCredentials: [], // TODO: fetch existing passkeys
                })
                return ctx.forward(c, await config.loginOptions(c.req.raw, opts))
            })
            routes.post("/passkey/login", async (c) => {
                // TODO: fetch passkey from database
                const passkey = {
                    id: "",
                    publicKey: "",
                    counter: 0,
                    transports: ["internal"]
                } as WebAuthnCredential
                const valid = await verifyAuthenticationResponse({
                    response: await c.req.formData() as AuthenticationResponseJSON,
                    expectedChallenge: "challenge", // TODO: fetch the challenge
                    expectedOrigin: RP_ORIGIN, // TODO: Android origin?
                    expectedRPID: RP_ID,
                    credential: passkey,
                })
                return ctx.forward(c, await config.login(c.req.raw, valid))
            })
        },
    } satisfies Adapter<{ email: string }>
}
