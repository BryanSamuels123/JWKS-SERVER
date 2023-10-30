// this is the test suite for server.js post and get requests will be tested along with the types that aren't specified
const fetch = require('node-fetch')
const testGet = async () => { // tests the get function 
    

    try {
        const resp = await fetch("http://localhost:8080/.well-known/jwks.json");
        const data = await resp.text();
        console.log("\n\nFinal get test:\n")
        console.log(data);
        console.log("\nPassed Final get Test\n")
    }
    catch(err){
        console.error("Error With 'testGet()':\n", err);
    }
    
};


const doPost = async (data) =>{ // constructs the post request
    const params = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }

    try{
        const dataStream = await fetch("http://localhost:8080/auth", params); // makes the post request
        const retData = await dataStream.text();

        console.log(`Passed test "POST"\nReturned data for variable ${data.username}:\n${retData}\n\n`)
    }
    catch(err){
        console.error(`Error With 'doPost()' for ${data.username}:\n`, err);
    }
    
}

const testPost = () => { // testing the post request against other 
    const users = [
        { "username": "jdoe001", "role": "user", "password": "password1" },
        { "username": "asmith002", "role": "admin", "PASSWORD": "password2", "expired": true },
        { "username": "bkim003", "role": "user", "pWORD": "password3" },
        { "username": "mjohnson004", "role": "user", "pword": "password4" },
        { "username": "rwilliams005", "role": "admin", "PASSWORD": "password5" },
        { "username": "klee006", "role": "user", "passWord": "password6", "expired": true },
        { "username": "schen007", "role": "user", "Password": "password7" },
        { "username": "lsmith008", "role": "admin", "Password": "password8" },
        { "username": "gadams009", "role": "user", "password": "password9" },
        { "username": "pwalker010", "role": "user", "password": "password10" },
        {}
      ];

    users.map((user) => {
        doPost(user);
    });
};

testPost();



testGet();
