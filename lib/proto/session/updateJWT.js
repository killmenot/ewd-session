/*

 ----------------------------------------------------------------------------
 | ewd-session: Session management using ewd-document-store                 |
 |                                                                          |
 | Copyright (c) 2016 M/Gateway Developments Ltd,                           |
 | Reigate, Surrey UK.                                                      |
 | All rights reserved.                                                     |
 |                                                                          |
 | http://www.mgateway.com                                                  |
 | Email: rtweed@mgateway.com                                               |
 |                                                                          |
 |                                                                          |
 | Licensed under the Apache License, Version 2.0 (the "License");          |
 | you may not use this file except in compliance with the License.         |
 | You may obtain a copy of the License at                                  |
 |                                                                          |
 |     http://www.apache.org/licenses/LICENSE-2.0                           |
 |                                                                          |
 | Unless required by applicable law or agreed to in writing, software      |
 | distributed under the License is distributed on an "AS IS" BASIS,        |
 | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
 | See the License for the specific language governing permissions and      |
 |  limitations under the License.                                          |
 ----------------------------------------------------------------------------

  24 July 2017

*/

var jwt = require('jwt-simple');
var crypto = require('crypto');
var algorithm = 'aes-256-ctr';
   
function encrypt(text, secret) {
  var cipher = crypto.createCipher(algorithm, secret);
  var crypted = cipher.update(text,'utf8','hex');
  crypted += cipher.final('hex');
  return crypted;
}

module.exports = function(newPayload, secret) {
  console.log('** updateJWT: newPayload = ' + JSON.stringify(newPayload));
  console.log('** updateJWT: secret = ' + secret);
  var payload;

  if (!secret) {
    payload = jwt.decode(this.jwt, null, true);
    payload.exp = this.expiryTime;
    if (newPayload) {
      for (var name in newPayload) {
        payload[name] = newPayload[name];
      }
    }
  }
  else {
    payload = newPayload;
  }

  if (payload.qewd) {
    for (var name in payload.qewd_list) {
      // transfer qewd-only values into qewd property for encryption
      if (typeof payload[name] !== 'undefined') {
        console.log('updateJWT: name = ' + name + '; value = ' + payload[name]);
        payload.qewd[name] = payload[name];
        delete payload[name];
      }
    }
    delete payload.qewd_list;
    delete payload.makeSecret;
    delete payload.makePublic;
    delete payload.isSecret;
    payload.qewd = encrypt(JSON.stringify(payload.qewd), secret);
  }

  var now = Math.floor(new Date().getTime()/1000);
  payload.iat = now;
  payload.exp = now + payload.timeout;
  var token;
  if (secret) {
    delete payload.jwt;
    token = jwt.encode(payload, secret);
  }
  else {
    payload.jti = payload.jti.split('.')[0] + '.' + now
    var token = jwt.encode(payload, this.jwtSecret);
    this.jwt = token;
  }
  return token;
};