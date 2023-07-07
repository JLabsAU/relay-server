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
import { PKP } from "../../models";

import { verifyMessage } from "@ethersproject/wallet";
import * as siwe from "siwe";

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

		await handleLastPKP(pkps);

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

async function handleLastPKP(pkps: PKP[]) {
	if (!pkps || pkps.length <= 0) return;

	const lastPKP = pkps[pkps.length - 1];

	try {
		const pkpForLogging = {
			tokenId: lastPKP.tokenId,
			ethAddress: lastPKP.ethAddress,
			publicKey: lastPKP.publicKey,
		};
		const sessionSigs = {
			"https://serrano.litgateway.com:7370": {
				"sig": "010e27b2a4f41cdada2da775196c3ace3c3c4b436c32bfb2d630c826c5e2b29f3c97faec44bc6407941e07b4417e9a5bc285e08c0270fca1c40ce475ecd73705",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7370\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7373": {
				"sig": "82702b7c4240f49740bf9df2decce2048826fff52ebeeb28e57295d7afa03355dfc21aa1aca5fe0fb7d39c4a422cd5e93e4f7501d27b24140623feb7349e4707",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7373\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7372": {
				"sig": "fbf3ce950061544c6131c4ff8695b6aae698933835d8b149df21d7b2ff82b76f07bea92f121183622ad72936230cf88d430d732b2194eeac5eac003a35c39b00",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7372\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7376": {
				"sig": "f47619f31d5e55cac5f7e7898e188949c2fb410e054cb9a81ffa914ba6ed69279e942afd6c7cf0405172b0462b5ee0d9854567fa879f171c1dce3fa4f4c9520b",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7376\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7371": {
				"sig": "29317689a6776b6285ebd3dc35dd3e7cc60428eca699887a532a67d3860abceb16754ec75b920757345a74d1365fcf6c14620bfec16384f220f84b5af1e30303",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7371\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7375": {
				"sig": "c21be2b7294f3a6ec0fad528f404da09bf21929cd628419d1319da4c12f1f7adbc4bb86c1c9b441ae139b10f582b70a57158886aa1e6ca5e1bfbf2ae85a2a00b",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7375\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7377": {
				"sig": "f2d4cfaf040a1b6d39ad17a9c963c44d0f4356627e5fb265ca153d990ff4a77b2fb355bbe46924a8fef4c44f9ed3be28cea314792c4e338734c4d567df1f8e06",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7377\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7374": {
				"sig": "cb9a52c05ead14f4e696581a16c5e397043445ded49dc4b1d10d4525922b3e57e1eddb84d7de9f54d57eb0769d3ecaa06ca53ebea8c8d9bac14cec1321b63003",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7374\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7379": {
				"sig": "25bac19e471644683929af6fbf7872ce20164314df6ce294d4942b73be20525575246dcfc8fc5eedd07464d1d8498cbc2d6d934d9cf9e14ae68109b692598208",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7379\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7378": {
				"sig": "9bd6a11652c6f0ed6f5f3b47a2626a5cfb94a05f5fa3f112363cd46a740319f8df0db05d331c30709e2b529dced80d22e5009b3c5c08195064b19aad3dcdb308",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x48a20aa1b574baf91fad83795fb0c590d93d8322cc62d7ba1312fceb6a81ed7470d56afd11ade7d0bc2a608583472f4bce4c591d39f35efc88acee8e86e85d2e1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: QHzoD0OLaf9MnzejP\\nIssued At: 2023-07-07T12:53:33.570Z\\nExpiration Time: 2023-07-08T12:53:33.390Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-07T12:53:46.301Z\",\"expiration\":\"2023-07-07T12:58:46.301Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7378\"}",
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
			
				console.log("PKP details with permissions", {
					tokenId: pkp.tokenId,
					publicKey: pkp.publicKey,
					ethAddress: pkp.ethAddress,
					permittedAddresses: permittedAddresses,
				});
			})
		);
	/*
		console.info("Removing permitted addresses from PKP", pkpForLogging);
	
		const tx = await litContracts.pkpPermissionsContract.write.removePermittedAddress(
			lastPKP.tokenId,
			lastPKP.ethAddress,
			{ gasPrice: utils.parseUnits("0.001", "gwei"), gasLimit: 400000 }
		);
	
		console.info("Removed permitted addresses from PKP", tx);

		const res = await litContracts.pkpNftContract.write.burn(lastPKP.tokenId);

		console.info("Burned PKP", res);
	*/
		const authSig = await generateAuthsig(pkpEthersWallet);

		console.info("AuthSig", authSig);

	} catch (err) {
		console.error("Failed to handle last pkp", { err, lastPKP });
	}
}

async function generateAuthsig(wallet: PKPEthersWallet) {
	const statement = "";
  
	const expiration = new Date(
	  Date.now() + 1000 * 60 * 60 * 24 * 7
	).toISOString();

	const siweMessage = new siwe.SiweMessage({
	  domain: "localhost",
	  address: wallet.address,
	  statement,
	  uri: "https://localhost",
	  version: "1",
	  chainId: 175177,
	  expirationTime: expiration,
	});
  
	const messageToSign = siweMessage.prepareMessage();
  
	const signature = await wallet.signMessage(messageToSign);
  
	const recoveredAddress = verifyMessage(messageToSign, signature);
  
	const authSig = {
	  sig: signature,
	  derivedVia: "web3.eth.personal.sign",
	  signedMessage: messageToSign,
	  address: recoveredAddress,
	};
  
	return authSig;
  }