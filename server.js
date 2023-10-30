/*
Bryan Samuels
bas0380
29 Oct 2023
CSCE 3550 Section 001
*/

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require("sqlite3").verbose();
const dbFile = "./totally_not_my_privateKeys.db";
const fs = require("fs");

const app = express();
const port = 8080;

let keyPair; // initalize needed vars
let expiredKeyPair;
let token;
let expiredToken;
let goodExp;
let badExp;

const createConn = () =>{
    const db = new sqlite3.Database(dbFile, (err) =>{ // connect to database
        if (err) return -1;
    });
    return db;
}

const createTable = () =>{
    const db = createConn();
    // execute schema script also makes database if not exists
    db.run("CREATE TABLE IF NOT EXISTS keys( kid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)", (err) =>{ 
        if (err){
            console.error(err);
        }
    });

    db.close();
}



async function generateKeyPairs() {
    keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' }); //use JOSE module to create both keypairs

    expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });   
}

function generateToken() { // generates the toke and signs using unexpired keypair
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000), // issed at time
    exp: Math.floor(Date.now() / 1000) + 3600 // time expires 3600 seconds is an hour
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

function generateExpiredJWT() { // the same function as above, but with expired times
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
  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options); // sign the JWT
}

app.all('/auth', (req, res, next) => { // handles wrong methods
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

app.get('/.well-known/jwks.json', (req, res) => { // handle get 
    const db = createConn(); // connect to database

    if (db === -1) res.status(500).send(JSON.stringify("")); // send bad request if error

    db.all("SELECT * FROM keys WHERE exp>(?)", [(Date.now()/ 1000)], (err, data) =>{ // selection query. Only finds valid pk
        if (err){
            console.error(err);
            res.status(500).send(JSON.stringify([]));
        }
        else {
            const promises = data.map((pemKey) => { // convert each to jwk format; async, must use promises
                return jose.JWK.asKey(pemKey.key, "PEM").then((key) => {
                    let JWK = key.toJSON();
                    JWK.alg = "RS256";
                    JWK.use = "sig";
                    return JWK;
                });
            });
    
            Promise.all(promises) // handle promises
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
});

app.post('/auth', (req, res) => {
    const db = createConn();
    if (db === -1) res.status(500).send([]); // handle bad connection

    let error = false;

    if (req.query.expired === 'true'){
        db.run("INSERT INTO keys (key, exp) values (?,?)", [keyPair.toPEM(true), badExp], (err) =>{ // add keys
            if (err){
                console.error(err); // handle error
                error = true;
            }
            else{  // send exp tokem
                res.status(200).send(expiredToken);
            }
        });

        
    }
    else{
        db.run("INSERT INTO keys (key, exp) values (?,?)", [keyPair.toPEM(true), goodExp], (err) =>{ // insertion query, add pk to database
            if (err){
                console.log(goodExp);
                console.error("error here",err);
                error = true;
            }
            else{
                res.status(200).send(token); // send cool token
            }
        });
    }
    db.close();
    if (error){
        res.status(500).send([]); // error/ semd bad response
    }
    
});

generateKeyPairs().then(() => { // async with promises: run server setup functions sequentially 
  generateToken()
  generateExpiredJWT()
  createTable() 
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`); // listen on port;
  });
});
