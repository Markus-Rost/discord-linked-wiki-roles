import { subtle } from 'node:crypto';
import gotDefault from 'got';
import { gotSsrf } from 'got-ssrf';
import pg from 'pg';
import DiscordOauth2 from 'discord-oauth2';
import botSettings from '../bots.json' with { type: 'json' };

/** @type {{[id: String]: {id: String, secret: String, key: CryptoKey, site: String, name: String, wiki: String, wiki_client: String, wiki_secret: String}}} */
export const SETTINGS = botSettings;
for (let site in SETTINGS) {
	SETTINGS[site].key = await subtle.importKey('raw', Buffer.from(SETTINGS[site].key, 'hex'), 'Ed25519', true, ['verify']).catch(console.log);
}

globalThis.isDebug = ( process.argv[2] === 'debug' );

export const oauth = new DiscordOauth2();

/*
CREATE TABLE linkedrole (
    discord  TEXT NOT NULL,
    userid   TEXT NOT NULL,
    username TEXT NOT NULL,
    site     TEXT NOT NULL,
    access   TEXT NOT NULL,
    refresh  TEXT NOT NULL,
    UNIQUE (
        discord,
        site
    )
);
*/
export const db = new pg.Pool().on( 'error', dberror => {
	console.log( `- Error while connecting to the database: ${dberror}` );
} );

export const got = gotDefault.extend( {
	throwHttpErrors: false,
	timeout: {
		request: 5000
	},
	headers: {
		'user-agent': 'Discord Linked Wiki Roles/' + ( isDebug ? 'testing' : process.env.npm_package_version ) + ' (Discord; ' + process.env.npm_package_name + ( process.env.invite ? '; ' + process.env.invite : '' ) + ')'
	},
	responseType: 'json'
}, gotSsrf );

export async function interactionCreate(interaction, site) {
	var result = {
		data: {
			flags: 64, // EPHEMERAL
			allowed_mentions: {
				parse: []
			}
		}
	};
	switch ( interaction.type ) {
		case 1: { // PING
			result.type = 1; // PONG
			break;
		}
		case 2: { // APPLICATION_COMMAND
			if ( interaction.data.type !== 1 ) break; // CHAT_INPUT
			interaction.user ??= interaction.member?.user;
			console.log( `${interaction.user.id}: Slash: /${interaction.data.name}` );
			switch ( interaction.data.name ) {
				case 'update': {
					result.type = 4; // CHANNEL_MESSAGE_WITH_SOURCE
					if ( await updateMetadata(interaction.user.id, site) ) {
						result.data.content = 'Your connection data has been updated.';
					}
					else result.data.content = 'No connection exists yet!';
					break;/*
					got.post( `https://discord.com/api/v10/applications/${id}/commands`, {
						json: {type:1,name:'update',description:'Update your connection data'},
						headers: {
							Authorization: `Bot ${token}`
						}
					} ).then( response => {
						return response.statusCode;
					} ); */
				}
			}
			break;
		}
	}
	if ( !result.type ) {
		result.type = 4; // CHANNEL_MESSAGE_WITH_SOURCE
		result.data.content = 'Unknown Interaction!';
	}
	return result;
}

/**
 * @param {String} user
 * @param {String} site
 */
export function updateMetadata(user, site) {
	var setting = SETTINGS[site];
	return db.query( 'SELECT userid, username, access, refresh FROM linkedrole WHERE discord = $1 AND site = $2', [user, site] ).then( ({rows:[row]}) => {
		if ( !row ) {
			console.log( `- No connection stored for ${user} on ${site}.` );
			return false;
		}
		got.put( `https://discord.com/api/v10/users/@me/applications/${setting.id}/role-connection`, {
			json: {
				platform_name: setting.name,
				platform_username: row.username,
				metadata: {}
			},
			headers: {
				Authorization: `Bearer ${row.access}`
			}
		} ).then( response => {
			var body = response.body;
			if ( response.statusCode !== 200 ) {
				console.log( `- ${response.statusCode}: Error while updating the data for ${user} on ${site}: ${body?.message||body?.error}` );
				if ( response.statusCode === 401 ) return refreshToken(user, site, row.refresh);
				return;
			}
			console.log( `- Updated data for ${user} as ${row.username} on ${site}` );
		}, error => {
			console.log( `- Error while updating the data for ${user} on ${site}: ${error}` );
		} );
		return true;
	}, dberror => {
		console.log( `- Error while gettings the user id for ${user} on ${site}: ${dberror}` );
	} );
}

/**
 * @param {String} user
 * @param {String} site
 * @param {String} token
 */
export function refreshToken(user, site, token) {
	var setting = SETTINGS[site];
	return oauth.tokenRequest( {
		grantType: 'refresh_token',
		refreshToken: token,
		scope: [ 'role_connections.write' ],
		redirectUri: process.env.redirect_uri + '/' + site,
		clientId: setting.id,
		clientSecret: setting.secret,
	} ).then( ({scope, access_token, refresh_token}) => {
		scope = scope.split(' ');
		if ( !scope.includes( 'role_connections.write' ) ) {
			return Promise.reject('Missing role_connections.write scope.' );
		}
		return db.query( 'UPDATE linkedrole SET access = $1, refresh = $2 WHERE discord = $3 AND site = $4', [access_token, refresh_token, user, site] ).then( () => {
			console.log( `- OAuth2 token for ${user} on ${site} successfully updated.` );
			return updateMetadata(user, site);
		}, dberror => {
			console.log( `- Error while saving the OAuth2 token for ${user} on ${site}: ${dberror}` );
		} );
	} ).catch( error => {
		console.log( `- Error while refreshing the Discord token: ${error}` );
		return db.query( 'DELETE FROM linkedrole WHERE discord = $1 AND site = $2', [user, site] ).then( () => {
			console.log( `- Deleted the connection for ${user} on ${site}` );
		}, dberror => {
			console.log( `- Error while deleting the connection for ${user} on ${site}: ${dberror}` );
		} );
	} );
}