//using provided JWKS servver file

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require("sqlite3").verbose();
const dbFile = "./totally_not_my_privateKeys.db";
const fs = require("fs");

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;
let goodExp;
let badExp;
let jwk;

const createConn = () =>{
    const db = new sqlite3.Database(dbFile, (err) =>{ // connect to database
        if (err) return -1;
    });
    return db;
}

const createTable = () =>{
    const db = createConn();
    // execute schema script
    db.run("CREATE TABLE IF NOT EXISTS keys( kid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)", (err) =>{ 
        if (err){
            console.error(err);
        }
    });

    db.close();
}



async function generateKeyPairs() {
    keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    // console.log(keyPair.toJSON());
    expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });   
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };
  goodExp = payload.exp;
  token = jwt.sign(payload, keyPair.toPEM(true), options);
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  badExp = payload.exp;
  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

// const  convertPemToJwk = async (pemKey) => {
//     try {
//       // Import the private key in PEM format
//       const privateKey = await jose.JWK.asKey(pemKey, 'pem');
  
//       // Convert the private key to a JWK
//       const jwk = privateKey.toJSON();
  
//       console.log('JWK:', JSON.stringify(jwk, null, 2));
//     } catch (error) {
//       console.error('Error:', error);
//     }
//   }

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
    let myJWKS = [];
    let status = 500;
    const db = createConn();
    if (db === -1) res.status(500).send(JSON.stringify(""));
    db.all("SELECT * FROM keys WHERE exp>(?)", [(Date.now()/ 1000)], (err, data) =>{
        if (err){
            console.error(err);
            res.status(500).send(JSON.stringify([]));
        }
        else {
            const promises = data.map((pemKey) => {
                return jose.JWK.asKey(pemKey.key, "PEM").then((key) => {
                    let JWK = key.toJSON();
                    JWK.alg = "RS256";
                    JWK.use = "sig";
                    return JWK;
                });
            });
    
            Promise.all(promises)
                .then((JWKS) => {
                    res.status(200).send({"keys": JWKS});
                })
                .catch((error) => {
                    console.error(error);
                    res.status(500).send(JSON.stringify([]));
                });
        }
    });
    db.close();
    // res.status(status).send(myJWKS);


//   const validKeys = [keyPair].filter(key => !key.expired);
//   res.setHeader('Content-Type', 'application/json');
//   res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.post('/auth', (req, res) => {
    const db = createConn();
    if (db === -1) res.status(500).send([]);

    let status = 500; // set default status and token to be sent
    let nToken = [];
    let error = false;

    if (req.query.expired === 'true'){
        db.run("INSERT INTO keys (key, exp) values (?,?)", [keyPair.toPEM(true), badExp], (err) =>{
            if (err){
                console.error("no error here" ,err);
                error = true;
            }
            else{
                // status = 200; // update status and token to be sent
                // nToken = expiredToken;
                res.status(200).send(expiredToken);
            }
        });

        
    }
    else{
        db.run("INSERT INTO keys (key, exp) values (?,?)", [keyPair.toPEM(true), goodExp], (err) =>{
            if (err){
                console.log(goodExp);
                console.error("error here",err);
                error = true;
            }
            else{
                res.status(200).send(token);
            }
        });
    }
    db.close();
    if (error){
        res.status(500).send([]);
    }
    
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  createTable()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
