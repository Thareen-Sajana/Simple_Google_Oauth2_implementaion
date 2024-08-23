const { Issuer, generators } = require('openid-client')
const model = require('../model/model')
const jwt = require('jsonwebtoken')

let googleClient;

exports.googleOauth = async (req, res) => {

    const state = generators.state();
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);

    // Save the auth state in the database :
    model.save_auth_state(state, code_challenge, req.originalUrl)

    res.cookie("code_verifier", code_verifier, {
        httpOnly: true,
        secure: true
    })

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
    const { code } = req.query;

    const codeVerifier = req.cookies.code_verifier

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
    if (!refreshToken) return res.status(401).send("Unauthorized")

    const result = await model.get_user_id(refreshToken);
    if (result.rows.length === 0) return res.status(401).send("Unauthorized");

    const userDetails = await model.get_user_details(result.rows[0].user_id)

    const user = {
        username : userDetails.rows[0].username,
        email : userDetails.rows[0].email,
    }

    const token = jwt.sign(user, process.env.JWT_SECRET, {expiresIn: '1h'});

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
    })
}

exports.users = async (req, res) => {

    res.json({data: "This is secured end point",
        name: req.user.username
    })
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