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
			"https://serrano.litgateway.com:7377": {
				"sig": "74a060f789dd22b78b2f938d9fd4c04f14bca90f723af7a2af7e5a205d019649480ac5cbacef3f3981314cc00f64b5555c498df52ddb5b36ce7d601df8502e06",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7377\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7374": {
				"sig": "8df7a85ca7099ebd6aa6188fdbb47827fc1862e1985c52401bcdd6d15aa0586389f0b85bbb998e05421d6c482ecdfd0a08f5e4a259470a46b9046badbdb6f607",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7374\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7376": {
				"sig": "afcd7044c50b7c9bfc78096c97244a78dea5a529adad2513debab7b4427e67a456089ea32252bf7c308e7bb2037815868662b55cf52a88c46088492aa1863b0a",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7376\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7372": {
				"sig": "16484f472d92dcb17070271267d9eaa9e0135a70386d9d074cdd219f6c78726abe2a224569fada1efee76054be2584a264e082fbe4493ce4c48106ce57d86c0b",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7372\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7370": {
				"sig": "4ffd03a255564902188e73db306cdd82746a885e85bf2fa52a393115feb32708ff7d6401522682ee0935c29b844b5694389841981ddae6288b0cca4adbd18900",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7370\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7379": {
				"sig": "62187efcd320601a22bf907d022d24893fe760d3a811888aa856b78365e1d8d13568b346b60f34f548f071eb2578671cb824e7d1e3968fcbd2697cc7b756ac09",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7379\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7378": {
				"sig": "9197128b94e7202542fb0a2f22d0cc76ec73414f758908af3e665f3db3ed285287417cc4bec589d096f54b6f12066ddfb8f837bb6330822f00e0da2bc8f02b00",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7378\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7371": {
				"sig": "998c17aefecce362b25e41e96a8876e5f31ba14ba8a00b2269b6bbcc5d04fe1deb568a16add67fe21b96d1bcb66232a7fcc3440e2c46b332d10edced7ac19606",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7371\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7373": {
				"sig": "6b5146d0d5ae073b7157ae861c830302b0a9579e63b9780b1921de96af3e803a82f20ab3b1c7f790498b8179df775881f5b039dabf5f1ef1561445a527b29708",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7373\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7375": {
				"sig": "5c5a0bafc88aabcc2a9548dd7f4868de92ae10f11b9e0eb0019f7aeca135ccebc7a9e46db030c166408003ed10a30f8496dac21c08e13783a2169bc13cdf3200",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0xda57c499704b7f1905be5c75f362c12c8091e30b92647a534762ae8061aa12933f44292895990dff054cf4d5b1ba346daa9b590d4c09ef5ce53c62ea8d3cae9d1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xA9f46debD103DAD171FB0491635b840C382a5753\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: 44WDYL2i23xjBWn0u\\nIssued At: 2023-06-27T11:28:15.389Z\\nExpiration Time: 2023-06-28T11:28:15.210Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xA9f46debD103DAD171FB0491635b840C382a5753\"}],\"issuedAt\":\"2023-06-27T11:28:19.234Z\",\"expiration\":\"2023-06-27T11:33:19.234Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7375\"}",
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
	} catch (err) {
		console.error("Failed to handle last pkp", { err, lastPKP });
	}
}