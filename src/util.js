import { createRequire } from 'node:module';
import gotDefault from 'got';
import { gotSsrf } from 'got-ssrf';
import pg from 'pg';
import DiscordOauth2 from 'discord-oauth2';
const require = createRequire(import.meta.url);
/** @type {{[id: String]: {id: String, secret: String, site: String, name: String, wiki: String, wiki_client: String, wiki_secret: String}}} */
export const SETTINGS = require('../bots.json');

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

/**
 * @param {String} user
 * @param {String} site
 */
export function updateMetadata(user, site) {
	var setting = SETTINGS[site];
	db.query( 'SELECT userid, username, access, refresh FROM linkedrole WHERE discord = $1 AND site = $2', [user, site] ).then( ({rows:[row]}) => {
		if ( !row ) {
			console.log( `- No connection stored for ${user} on ${site}.` );
			return;
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
			console.log(response.statusCode,response.body)
		}, error => {
			console.log( `- Error while updating the data for ${user} on ${site}: ${error}` );
		} );
	}, dberror => {
		console.log( `- Error while gettings the user id for ${user} on ${site}: ${dberror}` );
	} );
}