const { Issuer, generators } = require('openid-client')
const axios = require('axios')
const model = require('../model/model')
const util = require('util')
const jwt = require('jsonwebtoken')
const keys = require('../config/keys')

let googleClient;

exports.googleOauth = async (req, res) => {

    const state = generators.state();
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);

    // Save the auth state in the database :
    model.save_auth_state(state, code_challenge, req.originalUrl, code_verifier)

    let client = await getGoogleAuthClient();

    const authUrl = client.authorizationUrl({
        redirect_uri: process.env.REDIRECT_URI,
        scope: 'openid email profile',
        state: state,
        code_challenge: code_challenge,
        code_challenge_method: 'S256',
        access_type: 'offline'
    });

    res.redirect(authUrl)
}

exports.callback = async (req, res) => {
    const { state,code } = req.query;
    console.log("this is query L "+ JSON.stringify(req.query))

    const results = await model.get_code_verifier(state)
    const codeVerifier = results.rows[0].code_verifier;
    console.log("\n\n\nThis is code challaenge : "+ codeVerifier)
    //const codeVerifier = req.cookies.code_verifier

    const client = await getGoogleAuthClient();

    const tokenSet = await client.callback(process.env.REDIRECT_URI, { code }, { code_verifier: codeVerifier });
    const userinfo = await client.userinfo(tokenSet);

    const user =  await model.save_user(userinfo.name, userinfo.email)

    const refreshToken = generators.random(32)

    // Saving token details : 
    await model.save_user_token_details(user.rows[0].id, refreshToken, tokenSet.access_token, tokenSet.refresh_token)

    res.cookie('APP_REFRESH_TOKEN', refreshToken, { httpOnly: true, secure: true });
    res.redirect('/token');
}

exports.token = async (req, res) => {
    
    const refreshToken = req.cookies.APP_REFRESH_TOKEN;
    //const refreshToken = "L7QVEucyEj_oDTJ0JNU0lS_0zoaOywKNaEv_egC3J7I";
    if (!refreshToken) return res.status(401).send("Unauthorized")

    const result = await model.get_user_by_refreshToken(refreshToken);
    if (result.rows.length === 0) return res.status(401).send("Unauthorized");

    if (new Date() > new Date(result.rows[0].expiry)) return res.status(401).send('Unauthorized');

    const client = await getGoogleAuthClient();
    //console.log("this is results : "+ JSON.stringify(result.rows))
    //console.log("this is google access toekn : "+ result.rows[0].google_access_token)

    const is_token_valid = await validateGoogleAccessToken(result.rows[0].google_access_token);
    console.log("this is google : " + is_token_valid)

    if (!is_token_valid) {
        const new_token_set = await generateGoogleAccessToken(result.rows[0].google_refresh_token);

        if (new_token_set) {
            model.update_user_token_table(new_token_set.access_token, result.rows[0].user_id)
            console.log("\n\n\nexecute ......................\n\n\n")
        }else{
            return res.status(401).send("Unauthorized");  
        }
    }

    const userDetails = await model.get_user_details(result.rows[0].user_id)

    const user = {
        username : userDetails.rows[0].username,
        email : userDetails.rows[0].email,
        sub: userDetails.rows[0].id
    }

    const key = await keys.get_key();

    const token = jwt.sign(user, key.private_key, { algorithm: 'RS256' ,expiresIn: '1h'});

    res.json({ token })
    
}

exports.api_middleware = (req, res, next) => {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).send("Unauthorized");

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(401).send("Unauthorized");

        req.user = user;
        next();

    } catch(error) {
        return res.status(401).send("Unauthorized");
    }

}

exports.users = async (req, res) => {

    const users = await model.get_users(req.user.sub);
    res.json(users.rows);
    console.log("\n\n\n id : "+ req.user.sub)
}

getGoogleAuthClient = async () => {

    if(!googleClient) {

        const googleIssuer = await Issuer.discover('https://accounts.google.com');

        const googleClient = new googleIssuer.Client({
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uris: process.env.REDIRECT_URI,
            response_types: ['code'],
        }); 
        return googleClient;
    }
}

// exports.sign = async (req, res) => {
//     const { private_key} = await keys.get_key();
//     res.send(private_key)

// }