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

		const sessionSigs = {
			"https://serrano.litgateway.com:7370": {
				"sig": "dee2444744a1532ba0b40271547388b7b876963f47385111323b7116e41aff734132b2f53d552918bbd49d4df4c9d0e9b6ac6ff531cc6f06d49fe3bf02be6b05",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7370\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7371": {
				"sig": "4bfe9e7960e16663acfdd0009be6882c50800cc929dae57c6f55edc46b24c31938642391eb8598c24441ddc3a255a6cc1f035646f5338501ff51b89812dfee02",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7371\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7374": {
				"sig": "5c0b22850c3900efbafd2b68ebc7c5ee18d104e6835dc1fbd98a71a39dc82f8690e8b95877d6e14639ff47a9646b9ca4a489d15c2684ce0869014b1bca4cc00e",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7374\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7379": {
				"sig": "41a42566e978e44db892c4b46d7d67f43baa479e9861ce7364807aa5703908d0e5bc84daa4b6cbeab3a9fdb19aa7b98b343ba4829f1b381622fe968fe2165305",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7379\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7375": {
				"sig": "f268cc2986515e351d7431c47cdbc2314a0943463380047b12455b2f381467b29654b27446abd4d17a1bf0f203e081a7b2bbf9d79e28ceb8fda6ca5707a9460f",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7375\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7377": {
				"sig": "2c05e01759e7ffbd5864b89cef35fb0b2bb5b054ae1086a4af1e7d87fd6741f8107b68bf47420ab4d6c3e7a808922750a8931338bc2ad1698499c39ed2278000",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7377\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7378": {
				"sig": "cbf436b0d78ace3f46dd829e3a4d6bd2f0d7e3987b022c374303e42abd95bcab7942b338024a7f314d87b9ff3db3c8cf12c1536bc4f7d9fed93d145ba4d3d60d",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7378\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7372": {
				"sig": "eb04ba40f8734696a296d935656a93543c1fa5883baec2e6a8aebd5ad68427d5b9d1f50147e7e3aecc9b8ba40cf3abb867585c8652c536c48691de927bae770a",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7372\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7376": {
				"sig": "f6f23dd15b4074e5127a97e6752a9dbf7a59abc965644054a16ee4d4dbc0fb766cbbb6cb687571f0fdc951f783e5c440397f2dbca7c8f177dbfaba77d0d34607",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7376\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			},
			"https://serrano.litgateway.com:7373": {
				"sig": "dd5d216e989e865946e3246909aa710fae1e0e8f156bc807ebc7230b0b58e943b5f097fbc7cd19b8f5798a180494b2b1aa49ab43b9b1ae91020425ca8e00960a",
				"derivedVia": "litSessionSignViaNacl",
				"signedMessage": "{\"sessionKey\":\"6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\",\"resourceAbilityRequests\":[{\"resource\":{\"resource\":\"*\",\"resourcePrefix\":\"lit-accesscontrolcondition\"},\"ability\":\"pkp-signing\"}],\"capabilities\":[{\"sig\":\"0x7066309025833ccd9e0d27fe183a17de93b86e608d14c8afb8c0c66e75af1311208e735539e471b2472e1b1ac22ddd99328e4ddeb6ad813bf890280c30c1ddfb1b\",\"derivedVia\":\"web3.eth.personal.sign via Lit PKP\",\"signedMessage\":\"localhost:3000 wants you to sign in with your Ethereum account:\\n0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\\n\\nLit Protocol PKP session signature\\n\\nURI: lit:session:6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676\\nVersion: 1\\nChain ID: 1\\nNonce: DsAXf6fRIGedasDyV\\nIssued At: 2023-06-26T01:54:10.262Z\\nExpiration Time: 2023-06-27T01:54:10.087Z\\nResources:\\n- urn:recap:eyJhdHQiOnsibGl0LWFjY2Vzc2NvbnRyb2xjb25kaXRpb246Ly8qIjp7IiovKiI6W3t9XX19LCJwcmYiOltdfQ\",\"address\":\"0xC3CeC55c176FC47EeFFF06247A1a52918E7cfBC5\"}],\"issuedAt\":\"2023-06-26T01:54:14.158Z\",\"expiration\":\"2023-06-26T01:59:14.158Z\",\"nodeAddress\":\"https://serrano.litgateway.com:7373\"}",
				"address": "6894e83415d38630cef8805fedecfd672999659871c14bf6c9aed52560113676",
				"algo": "ed25519"
			}
		};

		const pkpEthersWallet = new PKPEthersWallet({
			controllerSessionSigs: sessionSigs,
			pkpPubKey: pkps[0].publicKey,
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

		const lastPKP = pkps[pkps.length - 1];
		const pkpForLogging = {
			tokenId: lastPKP.tokenId,
			ethAddress: lastPKP.ethAddress,
			publicKey: lastPKP.publicKey,
		};

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
