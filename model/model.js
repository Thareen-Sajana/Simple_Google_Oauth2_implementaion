
const db = require('../config/db')

exports.save_auth_state = async (state, code_challenge, url, code_verifier)=> {
    await db.query(
        'INSERT INTO auth_state (state, code_challenge, origin_url, code_verifier) VALUES ($1, $2, $3, $4)',
        [state, code_challenge, url, code_verifier]
    )
}

exports.get_code_verifier = (state) => {
    return db.query('SELECT code_verifier FROM auth_state WHERE state = $1', [state]);
}

exports.save_user = (name, email) => {
    return db.query(
        'INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id',
        [name, email])
}

exports.save_user_token_details = (user_id, app_refresh_token, google_access_token, google_refresh_token) => {
    db.query(
        'INSERT INTO user_token (user_id, app_refresh_token, google_access_token, google_refresh_token, expiry) VALUES ($1, $2, $3, $4, $5)',
        [user_id, app_refresh_token, google_access_token, google_refresh_token, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)])   
}

exports.get_user_by_refreshToken = (refreshToken) => {
    return db.query('SELECT * FROM user_token WHERE app_refresh_token = $1', [refreshToken]);
}

exports.get_user_details = (user_id) => {
    return db.query('SELECT * FROM users WHERE id = $1', [user_id]);
}

exports.get_users = async (user_id) => {

    await db.query(`SET LOCAL app.user_id = ${user_id}`);
    return await db.query('SELECT id, username, email FROM users WHERE id=$1', [user_id]);
}

exports.update_user_token_table = async (newToken, id) => {
    await db.query(
        'UPDATE user_token SET google_access_token = $1 WHERE user_id = $2',
        [newToken, id]
    );
}

exports.add_sign_keys = async (privateKey, publicKey, expirationTime) => {
    await db.query('INSERT INTO signing_key (private_key, public_key, expires_at) VALUES ($1, $2, $3)', [privateKey, publicKey, expirationTime]);
}

exports.get_sign_keys = async () => {
    return await db.query('SELECT * FROM signing_key WHERE expires_at > NOW() ORDER BY expires_at DESC LIMIT 1');
}