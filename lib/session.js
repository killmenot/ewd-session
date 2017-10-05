/*

 ----------------------------------------------------------------------------
 | ewd-session: Session management using ewd-document-store                 |
 |                                                                          |
 | Copyright (c) 2016-17 M/Gateway Developments Ltd,                        |
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

  7 September 2017

*/

var DEFAULT_DOCUMENT_NAME = require('./constants').DEFAULT_DOCUMENT_NAME;

function Session(documentStore, id, updateExpiry, documentName) {
  this.documentName = documentName || DEFAULT_DOCUMENT_NAME;
  this.documentStore = documentStore;
  if (id) {
    this.id =id;
  }
  else {
    this.id = this.next();
  }
  this.data = new documentStore.DocumentNode(this.documentName, ['session', this.id]);
  if (updateExpiry !== false) this.updateExpiry(); // will be deleted if expired already
}

// keep module.exports here to avoid circular require() calls issues
module.exports = Session;

var proto = Session.prototype;

Object.defineProperty(proto, 'exists', require('./proto/session/exists'));
Object.defineProperty(proto, 'token', require('./proto/session/token'));
Object.defineProperty(proto, 'expired', require('./proto/session/expired'));
Object.defineProperty(proto, 'authenticated', require('./proto/session/authenticated'));
Object.defineProperty(proto, 'expiryTime', require('./proto/session/expiryTime'));
Object.defineProperty(proto, 'application', require('./proto/session/application'));
Object.defineProperty(proto, 'timeout', require('./proto/session/timeout'));
Object.defineProperty(proto, 'allowedServices', require('./proto/session/allowedServices'));
Object.defineProperty(proto, 'socketId', require('./proto/session/socketId'));
Object.defineProperty(proto, 'ipAddress', require('./proto/session/ipAddress'));
Object.defineProperty(proto, 'jwt', require('./proto/session/jwt'));
Object.defineProperty(proto, 'jwtSecret', require('./proto/session/jwtSecret'));

proto.next = require('./proto/session/next');
proto.updateExpiry = require('./proto/session/updateExpiry');
proto.allowService = require('./proto/session/allowService');
proto.disallowService = require('./proto/session/disallowService');
proto.sendToSocket = require('./proto/session/sendToSocket');
proto.createJWT = require('./proto/session/createJWT');
proto.updateJWT = require('./proto/session/updateJWT');
proto.delete = require('./proto/session/delete');
