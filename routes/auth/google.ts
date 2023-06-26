import { Request } from "express";
import { Response } from "express-serve-static-core";
import { ParsedQs } from "qs";
import {
	AuthMethodType,
	GoogleOAuthVerifyRegistrationRequest,
	AuthMethodVerifyRegistrationResponse,
	AuthMethodVerifyToFetchResponse,
} from "../../models";
import { OAuth2Client, TokenPayload } from "google-auth-library";
import { utils } from "ethers";
import { toUtf8Bytes } from "ethers/lib/utils";
import { mintPKP, getPKPsForAuthMethod, getPermissionsContractWithParams } from "../../lit";
import { PKPEthersWallet } from "@lit-protocol/pkp-ethers";
import { LitContracts } from "@lit-protocol/contracts-sdk";

const CLIENT_ID =
	process.env.GOOGLE_CLIENT_ID ||
	"355007986731-llbjq5kbsg8ieb705mo64nfnh88dhlmn.apps.googleusercontent.com";

const client = new OAuth2Client(CLIENT_ID);

// Validate given Google ID token
async function verifyIDToken(idToken: string): Promise<TokenPayload> {
	const ticket = await client.verifyIdToken({
		idToken,
	});
	return ticket.getPayload()!;
}

// Mint PKP for verified Google account
export async function googleOAuthVerifyToMintHandler(
	req: Request<
		{},
		AuthMethodVerifyRegistrationResponse,
		GoogleOAuthVerifyRegistrationRequest,
		ParsedQs,
		Record<string, any>
	>,
	res: Response<
		AuthMethodVerifyRegistrationResponse,
		Record<string, any>,
		number
	>,
) {
	// get idToken from body
	const { idToken } = req.body;

	// verify Google ID token
	let tokenPayload: TokenPayload | null = null;
	try {
		tokenPayload = await verifyIDToken(idToken);
		console.info("Successfully verified Google account", {
			userId: tokenPayload.sub,
		});
	} catch (err) {
		console.error("Unable to verify Google account", { err });
		return res.status(400).json({
			error: "Unable to verify Google account",
		});
	}

	// mint PKP for user
	try {
		const authMethodId = utils.keccak256(
			toUtf8Bytes(`${tokenPayload.sub}:${tokenPayload.aud}`),
		);
		const mintTx = await mintPKP({
			authMethodType: AuthMethodType.GoogleJwt,
			authMethodId,
			authMethodPubkey: "0x",
		});
		console.info("Minting PKP with Google auth", {
			requestId: mintTx.hash,
		});
		return res.status(200).json({
			requestId: mintTx.hash,
		});
	} catch (err) {
		console.error("Unable to mint PKP for given Google account", { err });
		return res.status(500).json({
			error: "Unable to mint PKP for given Google account",
		});
	}
}

// Fetch PKPs for verified Google account
export async function googleOAuthVerifyToFetchPKPsHandler(
	req: Request<
		{},
		AuthMethodVerifyToFetchResponse,
		GoogleOAuthVerifyRegistrationRequest,
		ParsedQs,
		Record<string, any>
	>,
	res: Response<AuthMethodVerifyToFetchResponse, Record<string, any>, number>,
) {
	// get idToken from body
	const { idToken } = req.body;

	// verify idToken
	let tokenPayload: TokenPayload | null = null;
	try {
		tokenPayload = await verifyIDToken(idToken);
		console.info("Successfully verified Google account", {
			userId: tokenPayload.sub,
		});
	} catch (err) {
		console.error("Unable to verify Google account", { err });
		return res.status(400).json({
			error: "Unable to verify Google account",
		});
	}

	// fetch PKPs for user
	try {
		const idForAuthMethod = utils.keccak256(
			toUtf8Bytes(`${tokenPayload.sub}:${tokenPayload.aud}`),
		);
		const pkps = await getPKPsForAuthMethod({
			authMethodType: AuthMethodType.GoogleJwt,
			idForAuthMethod,
		});

		console.info("Fetched PKPs with Google auth", {
			pkps: pkps,
		});

		const lastPKP = pkps[pkps.length - 1];
		const pkpForLogging = {
			tokenId: lastPKP.tokenId,
			ethAddress: lastPKP.ethAddress,
			publicKey: lastPKP.publicKey,
		};
		const sessionSigs = {
			"https://serrano.litgateway.com:7370": {
				"sig": "3e3dd6cf514e4864dc43c139b7f1d904831a4d805c32eebc5a171a78387b17d0f7b2d0726888f1c96e411c02b0ab1957b81e6584f8698709aa6e5417ce637c0c",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7370\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7371": {
				"sig": "083f8ec29a1bbf5de567bc5a59bb44a9fc6870b920d798a806c8e4a91a0aad4079b27824cb466d714e8be4f0a664102aac3b5e92b1b62c18ad7c6e589cb0c505",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7371\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7373": {
				"sig": "aa5eb039ed05977c981fe440973d80666c87fb87a61563d357e7a46af900904492029bfcb65eff88bc18db696a89df83055d58465083aa1fa57cf1b109d11502",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7373\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7377": {
				"sig": "3d5463abb5b6adb0c873d28f72c091f51c81fde4c2eeed423ca5b94f7ee8700871c3aa97e2bf9ca501ab9eeb6c21692e53fd60cdf778a6afc59266603caa0401",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7377\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7375": {
				"sig": "9497d5e3f7ef892946a8499310ec8ec79ae15c701cd13833d71cfcf561afedf68150c42357f4a2bb6f82571013c73862f259bad764c38dbd98f83063812f710b",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7375\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7372": {
				"sig": "7f5c8f15d8e54888bb3d6e5a0fac75a8b519931d590889232ef2b07c16deef4867f682e3a4995408679544c56ec9bf5282a52f88202a91c7306a766d7b7ca005",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7372\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7376": {
				"sig": "3363ac43dd1de6103f5c7d82928868bed9343a5e28bc0ea0429d22f65ad449d44b91e5eb94baa42e6b2ec683852e1617ffa268d181f639905be084e59ae69207",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7376\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7379": {
				"sig": "e7e8d90547ca0cf454e9f041e051c2cc9b8114541c87d2b5e3c0dd10581db66fa16fd918a9884fbc256091d1a8917a8aa845cf49886d614d24f4f05b9d5ff202",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7379\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7378": {
				"sig": "e16c1c506732b5ce82211b9bd5c3c93e0eef996225cf1c3d04525bc4bae1726cb83e26e2b2b4bd6d58661e58d3f40ce8ed2b6967a4806f9bfd286028d98a0a05",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7378\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7374": {
				"sig": "873a9757a0b50035c6e8145110b1735199160fb78e90817c3fe5e5b2e1425970b7f847221a042e917c0350e1bcbca46e5405e0ffb7115254d711fd8525d9560c",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x6ebc940da1695a9da05443a35b3830e795284b74ead0ef842917587ab96f425f7b9dece83fe429f5ebb8ef880697e6bb3c718d6622e31936fd9c69104491f7e91c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: a0gtERcTJVYSH2UAX\\nIssued At: 2023-06-26T15:42:34.088Z\\nExpiration Time: 2023-06-27T15:42:33.928Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x4C07b20Dd2969D15A0acdb42cd9Ed85b64b87841\"}],\"issuedAt\":\"2023-06-26T15:42:38.002Z\",\"expiration\":\"2023-06-26T15:47:38.002Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7374\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			}
		};

		const pkpEthersWallet = new PKPEthersWallet({
			controllerSessionSigs: sessionSigs,
			pkpPubKey: lastPKP.publicKey,
			rpc: process.env.LIT_TXSENDER_RPC_URL,
			debug: false,
		  });
		await pkpEthersWallet.init();

		const litContracts = new LitContracts({
		signer: pkpEthersWallet,
		});
		await litContracts.connect();

		await Promise.all(
			pkps.map(async (pkp) => {
				const permittedAddresses = await litContracts.pkpPermissionsContract.read.getPermittedAddresses(pkp.tokenId);	
			
				console.log("PKP permissions", {
					tokenId: pkp.tokenId,
					publicKey: pkp.publicKey,
					ethAddress: pkp.ethAddress,
					permittedAddresses: permittedAddresses,
				});
			})
		);

		console.info("Removing permitted addresses from PKP", pkpForLogging);

		await litContracts.pkpPermissionsContract.write.removePermittedAddress(
			lastPKP.tokenId,
			lastPKP.ethAddress,
			{ gasPrice: utils.parseUnits("0.001", "gwei"), gasLimit: 400000 }
		);

		console.info("Removed permitted addresses from PKP", pkpForLogging);

		return res.status(200).json({
			pkps: pkps,
		});
	} catch (err) {
		console.error("Unable to fetch PKPs for given Google account", { err });
		return res.status(500).json({
			error: "Unable to fetch PKPs for given Google account",
		});
	}
}
