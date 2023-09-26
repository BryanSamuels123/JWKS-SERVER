const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const express = require("express");
const bodyParser = require('body-parser');
let jwt = require("jsonwebtoken")

// initialize server and request parsing
const app = express();
app.use(bodyParser.json()); 
app.use(express.json());
app.listen(8080, ()=> console.log("Server is listening on port 8080"));


// helper functions to generate the KID and the expiry timestamp
const generateKID = () => (crypto.randomBytes(16).toString("hex")); // generate a random keyID
const getExp = () => {
    const curr = new Date();
    expiresAtEpoch =  (Math.floor(curr.getTime() / 1000)) + 3600;
    return expiresAtEpoch;
}


app.get('/.well-known/jwks.json', (req, res) =>{ //get request
    console.log("I got a request")
    let jFile = [];
    let fin = [];

    if (fs.existsSync('./jwks/myJWKS.json')) { // checking if the JWKS exists
        // read file
        fs.readFile("./jwks/myJWKS.json", (err, data) => {
            if (err){
                console.error(err);
                return;
            }

            
            jFile = JSON.parse(data); // initialize object

            jFile.forEach((element) => { // loop through the array and find the valid tokens
                if (element.eat >= (getExp() - 3600)){
                    fin.push(element);
                }
            });
            
            res.status(200).send(JSON.stringify(fin)); // send the JWK
        });
        
    }
    else{
        res.status(200).send(JSON.stringify(fin)); // send empty array if no keys exist
    }
});

app.post('/auth', (req, res) => { // finish post request

    const {publicKey, privateKey} = crypto.generateKeyPairSync("rsa", { // generate public and private keys
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    if (!fs.existsSync('./pks')) { // checking if the folder that the private keys will be saved in exists
        fs.mkdirSync('./pks', { recursive: true });
    }
    let jFile = [];

    if (!fs.existsSync('./jwks/myJWKS.json')) { // checking if the folder that the JWKS will be saved in exists
        fs.mkdirSync('./jwks', { recursive: true });
    }
    else {
        jFile = fs.readFileSync("./jwks/myJWKS.json");
        jFile = JSON.parse(jFile);
    };

    const kid = generateKID(); // using the kid as the name for the pk for ease of searching
    const eat = (!req.body.expired) ? getExp() : (getExp() - 3601); // get expires at time.
    const file = `${kid}+${eat}.pem`; //plus sign is the delimiter
    const fPath = path.join("./pks", file); //joins path

    fs.writeFile(fPath, privateKey, (err) => { // write the private key to the file.
        if (err) {
          console.error('Error writing to file:', err);
        } else {
          console.log(`File ${file} created and data saved successfully.`);
        }
    });

    let tempPk = crypto.createPublicKey(publicKey);
    tempPk = tempPk.export({ format: 'jwk' });

    const jwk = {
        'kid': kid,
        'alg': 'RS256',
        'kty': 'RSA',
        'use': 'sig',
        'eat': eat,
        'n': tempPk.n,
        'e': tempPk.e
    };

    jFile.push(jwk);
    // save jwk for reuse
    fs.writeFileSync('./jwks/myJWKS.json', JSON.stringify(jFile), (err) => { // write the private key to the file.
        if (err) {
        console.error('Error writing to file:', err);
        } else {
        console.log(`data saved successfully`);
        }
    });

    const headers = { // set header
        algorithm: "RS256",
    }

    const payload =  req.body; // set payload
    payload["eat"] = eat;
    payload["kid"] = kid;

    const jwToken = jwt.sign(payload, privateKey, headers); // sign token
    res.status(200).send(jwToken); // send key

})


















/*
What needs to be done:

    1. The get JWKS needs to return the jwks that are available:
    multiple jwt will exist due to the requirements of the assignment.
    
    2. the post needs to make a jwk and a jwt due to the requirements.
        The jwt is signed by the private key and given the same expiry as the jwk.
        The client side can then verify the jwt using the public key 
    
    This is all that's required for this assignment, its really simple.
    (Technically don't need the saved private key for anything else other than displaying the expired pairs)

    3. make tests.

*/

// /auth returns a jwt on post request that is signed by the private key, the client can access public key to verify the signature.
// the kid must match the public key that corresponds to the private key.
// so if expired, create a new jwk, if not keep using the same jwt, keep the private key saved on the server
// in this case the professor wants us to keep the old expired key pairs, creating the jwt is easy,







