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
				"sig": "f983caffa7be71132014842339b39bd46c0637dd266979a6adcab3bfbc0d119a386f7b7abd89044c856f5cf16ab4b533f3618e5bccfa23884590060898d8ac08",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7370\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7374": {
				"sig": "a0a64bb8bb8f4d0acc9369f143a6d18c3d6b675ad2cde0f41db11eac554af05564b2fedbc8a134ab4cec6a00b5460afd25ea6f98a0abd564c1f05dcfdf17f204",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7374\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7371": {
				"sig": "d352147ca9f143b8e3653b159d9f1c73e8c946d0dc751ac7313e5cf6f025afb614f7add84307b3ec1b652bb0df7ccdf9742406e62829f2a00110f27415961803",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7371\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7373": {
				"sig": "271e8a6dec56a8d47f7afaa19e2b9db3de0574f72019fc9118039c101a413befe5609a0dc955325947cb9e2db0ca057b18fa1f819cf9676f8794bb0dcb8d4706",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7373\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7375": {
				"sig": "70ac398f71a8e4b1ffe0e44d40176cb11e7dc0f68a59fae409a51f4006009fa86ea869f4e52a2e908cac23ebeab80ac883521bb4b2fdcd6fe81bece9e0d2150f",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7375\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7372": {
				"sig": "8edd7b27691cc333452ad90bee9f37f515f7210adc0d7ed2b05a0fb3237a1b3a33a445bf689fd8b4760929db2f12dff8a7f754f2b4cb29c3c305b3a1284d5f00",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7372\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7376": {
				"sig": "6d14559ba3caf7907d9bd3dc873335525b8f5dd03499f2874247e94947e3070a5e45d4ab87f684f8b2a5a4d1542563443fe544d1e7df66ed6210d5686c075d0d",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7376\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7378": {
				"sig": "804088215af9caeab814a5f8530dd1bbf52758f447bda18542b28d03bd8b3f92af9391a2d6fb4e27becf63dd1e9b4598bff0b891dee66b6e00bb6c0d97860202",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7378\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7377": {
				"sig": "d86f62690c289d00b15fd0639ccbe6696163404e0ab17211e4475531036abb31ad64ddb90bcc15ac5b5ad2e5ce47e2f2058ab3efdfaf6f9a7aaac36ae3856f0b",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7377\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7379": {
				"sig": "410dd15499d6a24b85b9fbc84005a45c01876586015d626d47b6aec1c528a0d5dc5ed7291e2c45bdc4d6c2c3175b3119bcc9cca174d8ff2aeeaa84e81cd75b0d",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x71f5512f4850732b01ea1adefc82a87b3acd11094752c9b135bf3b513b8358e557197dc11c59db4f805e0f260ef3ebad10fa48321973b5abdc7cbd0333839d941c\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: lzl6oAU2mpUR65TIt\\nIssued At: 2023-07-06T13:06:47.799Z\\nExpiration Time: 2023-07-07T13:06:47.633Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-07-06T13:06:53.187Z\",\"expiration\":\"2023-07-06T13:11:53.187Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7379\"}",
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
	
		const tx = await litContracts.pkpPermissionsContract.write.removePermittedAddress(
			lastPKP.tokenId,
			lastPKP.ethAddress,
			{ gasPrice: utils.parseUnits("0.001", "gwei"), gasLimit: 400000 }
		);
	
		console.info("Removed permitted addresses from PKP", tx);

		const res = await litContracts.pkpNftContract.write.burn(lastPKP.tokenId);

		console.info("Burned PKP", res);

	} catch (err) {
		console.error("Failed to handle last pkp", { err, lastPKP });
	}
}