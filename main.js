import 'dotenv/config';
import { createServer, STATUS_CODES } from 'node:http';
import { subtle, randomBytes } from 'node:crypto';
import { SETTINGS, oauth, db, got, interactionCreate, updateMetadata } from './src/util.js';

/** @type {Map<String, {site: String, user: String, access_token: String, refresh_token: String}>} */
const tokenCache = new Map();

const server = createServer( (req, res) => {
	var reqURL = new URL(req.url, process.env.redirect_uri);

	if ( req.method === 'POST' ) {
		const signature = req.headers['x-signature-ed25519'];
		const timestamp = req.headers['x-signature-timestamp'];
		if ( !signature || !timestamp || !reqURL.pathname.startsWith('/linked_role/') ) {
			res.statusCode = 401;
			return res.end();
		}
		let parts = reqURL.pathname.replace('/linked_role/', '').split('/');
		if ( parts.length !== 1 || !SETTINGS.hasOwnProperty(parts[0]) ) {
			res.statusCode = 401;
			return res.end();
		}
		const setting = SETTINGS[parts[0]];
		if ( !setting.key || typeof setting.key === 'string' ) {
			res.statusCode = 401;
			return res.end();
		}

		let body = [];
		req.on( 'data', chunk => {
			body.push(chunk);
		} );
		req.on( 'error', () => {
			console.log( error );
			res.end('error');
		} );
		return req.on( 'end', async () => {
			const rawBody = Buffer.concat(body).toString();
			try {
				if ( !await subtle.verify('Ed25519', setting.key, Buffer.from(signature, 'hex'), Buffer.from(timestamp + rawBody)) ) {
					res.statusCode = 401;
					return res.end();
				}
			}
			catch ( verifyerror ) {
				console.log( verifyerror );
				res.statusCode = 401;
				return res.end();
			}
			try {
				let response = JSON.stringify( await interactionCreate( JSON.parse(rawBody), setting.site ) );
				res.writeHead(200, {
					'Content-Length': Buffer.byteLength(response),
					'Content-Type': 'application/json'
				});
				res.write( response );
				res.end();
			}
			catch ( jsonerror ) {
				console.log( jsonerror );
				res.statusCode = 500;
				return res.end();
			}
		} );
	}

	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
	res.setHeader('Content-Type', 'text/html');
	res.setHeader('Content-Language', ['en']);

	if ( req.method !== 'GET' ) {
		let body = '<img width="400" src="https://http.cat/418"><br><strong>' + STATUS_CODES[418] + '</strong>';
		res.writeHead(418, {
			'Content-Length': Buffer.byteLength(body)
		});
		res.write( body );
		return res.end();
	}

	if ( reqURL.pathname === '/linked_role' ) {
		if ( !reqURL.searchParams.get('code') || !reqURL.searchParams.get('state') ) {
			res.writeHead(302, {Location: '/'});
			return res.end();
		}
		let state = reqURL.searchParams.get('state');
		if ( !tokenCache.has(state) ) {
			res.writeHead(302, {Location: '/'});
			return res.end();
		}
		const tokens = tokenCache.get(state);
		const setting = SETTINGS[tokens.site];
		return got.post( `${setting.wiki}rest.php/oauth2/access_token`, {
			form: {
				grant_type: 'authorization_code',
				code: reqURL.searchParams.get('code'),
				redirect_uri: process.env.redirect_uri,
				client_id: setting.wiki_client,
				client_secret: setting.wiki_secret
			}
		} ).then( response => {
			/** @type {{access_token: String}} */
			var body = response.body;
			if ( response.statusCode !== 200 || !body?.access_token ) {
				console.log( `- ${response.statusCode}: Error while getting the wiki OAuth2 token on ${setting.wiki}: ${body?.message||body?.error}` );
				res.writeHead(302, {Location: '/'});
				return res.end();
			}
			return got.get( `${setting.wiki}rest.php/oauth2/resource/profile`, {
				headers: {
					Authorization: `Bearer ${body.access_token}`
				}
			} ).then( uresponse => {
				/** @type {{sub: String, username: String}} */
				var user = uresponse.body;
				if ( uresponse.statusCode !== 200 || !user?.sub || !user?.username ) {
					console.log( `- ${uresponse.statusCode}: Error while getting the mediawiki profile on ${setting.wiki}: ${user?.message||user?.error}` );
					res.writeHead(302, {Location: '/'});
					return res.end();
				}
				tokenCache.delete(state);
				db.query(
					'INSERT INTO linkedrole(discord, userid, username, site, access, refresh) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (discord, site) DO UPDATE SET username = EXCLUDED.username, access = EXCLUDED.access, refresh = EXCLUDED.refresh',
					[tokens.user, user.sub, user.username, setting.site, tokens.access_token, tokens.refresh_token]
				).then( () => {
					console.log( `- OAuth2 token for ${tokens.user} as ${user.username} on ${setting.site} successfully saved.` );
					updateMetadata(tokens.user, setting.site);
					let text = `<body style="display: flex; justify-content: center; align-items: center;"><big>You can close this tab now!</big></body>`;
					res.writeHead(200, {
						'Content-Length': Buffer.byteLength(text)
					});
					res.write( text );
					return res.end();
				}, dberror => {
					console.log( `- Error while saving the OAuth2 token for ${tokens.user} as ${user.username} on ${setting.site}: ${dberror}` );
					res.writeHead(302, {Location: '/'});
					return res.end();
				} );
			}, error => {
				console.log( `- Error while getting the mediawiki profile on ${setting.wiki}: ${error}` );
				res.writeHead(302, {Location: '/'});
				return res.end();
			} );
		}, error => {
			console.log( `- Error while getting the wiki OAuth2 token on ${setting.wiki}: ${error}` );
			res.writeHead(302, {Location: '/'});
			return res.end();
		} );
	}

	if ( !reqURL.pathname.startsWith('/linked_role/') ) {
		res.writeHead(302, {Location: '/'});
		return res.end();
	}
	let parts = reqURL.pathname.replace('/linked_role/', '').split('/');
	if ( parts.length !== 1 || !SETTINGS.hasOwnProperty(parts[0]) ) {
		res.writeHead(302, {Location: '/'});
		return res.end();
	}
	const setting = SETTINGS[parts[0]];
	if ( !reqURL.searchParams.get('code') ) {
		let oauthURL = oauth.generateAuthUrl({
			responseType: 'code',
			prompt: 'none',
			scope: [
				'identify',
				'role_connections.write'
			],
			redirectUri: process.env.redirect_uri + '/' + setting.site,
			clientId: setting.id,
		});
		res.writeHead(302, {Location: oauthURL});
		return res.end();
	}
	return oauth.tokenRequest( {
		grantType: 'authorization_code',
		code: reqURL.searchParams.get('code'),
		scope: [
			'identify',
			'role_connections.write'
		],
		redirectUri: process.env.redirect_uri + '/' + setting.site,
		clientId: setting.id,
		clientSecret: setting.secret,
	} ).then( ({scope, access_token, refresh_token}) => {
		scope = scope.split(' ');
		if ( !scope.includes( 'identify' ) || !scope.includes( 'role_connections.write' ) ) {
			console.log( `- Insufficient scopes authorized: ${scope.join(' ')}` );
			res.writeHead(302, {Location: '/'});
			return res.end();
		}
		oauth.getUser(access_token).then( user => {
			let state = `${setting.id}${Date.now().toString(16)}${randomBytes(16).toString('hex')}${user.id}`;
			while ( tokenCache.has(state) ) {
				state = `${setting.id}${Date.now().toString(16)}${randomBytes(16).toString('hex')}${user.id}`;
			}
			tokenCache.set(state, {
				site: setting.site,
				user: user.id,
				access_token,
				refresh_token
			});
			let oauthURL = `${setting.wiki}rest.php/oauth2/authorize?` + new URLSearchParams({
				response_type: 'code', state,
				redirect_uri: process.env.redirect_uri,
				client_id: setting.wiki_client
			}).toString();
			res.writeHead(302, {Location: oauthURL});
			return res.end();
		}, error => {
			console.log( `- Error while getting the Discord user: ${error}` );
			res.writeHead(302, {Location: '/'});
			return res.end();
		} );
	}, error => {
		console.log( `- Error while getting the Discord token: ${error}` );
		res.writeHead(302, {Location: '/'});
		return res.end();
	} );
} );

server.listen( process.env.server_port, process.env.server_hostname, () => {
	console.log( `- Server running at http://${process.env.server_hostname}:${process.env.server_port}/` );
} );

process.on( 'warning', warning => {
	if ( warning?.name === 'ExperimentalWarning' ) return;
	console.log(`- Warning: ${warning}`);
} );

/**
 * End the process gracefully.
 * @param {NodeJS.Signals} signal - The signal received.
 */
function graceful(signal) {
	console.log(signal);
	server.close( () => {
		console.log( '- ' + signal + ': Closed the server.' );
		db.end().then( () => {
			console.log( '- ' + signal + ': Closed the database connection.' );
			process.exit(0);
		}, dberror => {
			console.log( '- ' + signal + ': Error while closing the database connection: ' + dberror );
		} );
	} );
}

process.on( 'SIGHUP', graceful );
process.on( 'SIGINT', graceful );
process.on( 'SIGTERM', graceful );
process.on( 'SIGINT SIGTERM', graceful );