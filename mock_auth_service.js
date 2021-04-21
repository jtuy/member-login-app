var axios = require('axios');

//TODO - Make this worthwhile.
function mock_auth_service(req, res){
  console.log("Hit /mockAuthService endpoint from " + req.headers["x-forwarded-for"])
  res.setHeader('Content-Type', 'application/json');
  res.json({
    AuthResult: 'SUCCESS',
    username: req.body.username,
    firstName: "Jason",
    lastName: "Doe",
    email: "janed@zimt.okta.com",
    // globalID: 123456799
  })
}

module.exports = mock_auth_service
