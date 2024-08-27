const crypto = require('crypto')
const model = require('../model/model')

generate_key_pair = async ()=>  {
    const { publicKey, privateKey } =  crypto.generateKeyPairSync( 'rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    })

    const expirationTime = new Date(Date.now() + 3 * 30 * 24 * 60 * 60 * 1000);

    model.add_sign_keys(privateKey, publicKey, expirationTime)
    console.log("this is public : "+ publicKey)
    console.log("this is private : "+ privateKey)

    return { private_key: privateKey, public_key: publicKey, expires_at: expirationTime };
}


exports.get_key = async () => {

    const result = await model.get_sign_keys();

    if (result.rowCount > 0) {
        return result.rows[0];
    } else {
        return await generate_key_pair();
    }
}