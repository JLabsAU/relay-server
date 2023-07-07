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

	const lastPKP = pkps[pkps.length - 2];

	try {
		const pkpForLogging = {
			tokenId: lastPKP.tokenId,
			ethAddress: lastPKP.ethAddress,
			publicKey: lastPKP.publicKey,
		};
		const sessionSigs = {
			"https://serrano.litgateway.com:7370": {
				"sig": "f4832ee13caedc6ef76d2690b4412f7d728166287e5d326442f8b1115d0cf0cb39e08518e4c27c79723b22bc59eb16523ecb57ab73200d89adc30ff5721b0102",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7370\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7371": {
				"sig": "059cc6fc4c89a08b783dd26b41e0444e059d77779d3651c9d5b3c72fbd659b9704c746e5692b5476ae4f382ab87ecb812ce306a84c01a92775a0b789a1aeb20f",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7371\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7378": {
				"sig": "fbf72c87fdf4df4b5ca956d004cc3141f12ccd06cecd2feb3c9ba67b9f85592db1909ad6075edd730bea6435a981ef3f4a8f381c5aeaf078709b8e16a9d0090c",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7378\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7374": {
				"sig": "bfb908b125722fdc253cf4d0a7863a748c5f563fc88c228567e5d52947faa5168811da927218dd1025fde33ac914d9efa4e0bff22cccfda1448b42a13a382f0c",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7374\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7375": {
				"sig": "0a6cb1cee8ef011f8ce6cacb5df537019cb066610a6bb5dc9d14ee73da6d98bb17a1537a7c513155c3b30810623df7285946018cb45a34d0d450bb100339a704",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7375\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7376": {
				"sig": "c7fb445d0099fffd8fba6e79cd69d48748cc3fd2d82b0933828851c3f896116c72de44415391b74f129c2be25c58253bfce543947dfda190021a1b48b987f709",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7376\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7377": {
				"sig": "edc4c80b326266df40e1cc3ca4c630f71d47efacb5e776ef54e438a0f7439da259bd916e92417e3aa01b1a8bb48c5cad582fcf8203c8bd3b8689e3163303e006",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7377\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7373": {
				"sig": "19f50ce5f9b56a2977baa2f0c243f6395da3c40c97fc70c071cf36944f4be948bd8652dac673ffa78f99b4f8b9b942c0830b3bc65f48cea7fc4e5e3635baea06",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7373\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7379": {
				"sig": "aefad52231905d785a2045e768fefd0b01c69e6974a9bac11dc9fc35e1f0ced6b13a8bbbc339705e887ddc537480837357dfd9c5c749f159432697eed8532a0a",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7379\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7372": {
				"sig": "e7776143cfcbfcf3c18a6faa9560a6feeacfecdc95367231eb196b62a4eaa15cbd0f985f364241970111920f97f6bf187420c8cab15d9579a27c45c2a319a805",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xddaa6bc73bec0d3bfb6f61a409807e07ab9f88e6add1f2a19b539b6ddebfc7b8067335ab2ffd7d3233f051ed1c31d4d68e5afe3ceb0a11652c77a69ac775f2601b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: OEBRxltmPzRKLmbDY\\nIssued At: 2023-07-07T10:47:48.407Z\\nExpiration Time: 2023-07-08T10:47:48.241Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0x8C433380fF7c82dE5A2e10D5D1853B56a2Ef24Aa\"}],\"issuedAt\":\"2023-07-07T10:47:52.339Z\",\"expiration\":\"2023-07-07T10:52:52.339Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7372\"}",
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