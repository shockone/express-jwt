var jwt = require('jsonwebtoken');

module.exports = function(options) {
  if (!options || !options.secret) throw new Error('secret should be set');

  return function(req, res, next) {
    var token;
    if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        var scheme = parts[0]
          , credentials = parts[1];
          
        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        return res.send(401, {error: 'Bad format of the Authorization header. Should be "Authorization: Bearer [token]".'});
      }
    } else {
      return res.send(401, {error: 'No Authorization header was found.'});
    }

    jwt.verify(token, options.secret, options, function(err, decoded) {
      if (err) return res.send(401,{error: 'Verification failed. ' + err});
      req.user = decoded;
      next();
    });
  };
};
