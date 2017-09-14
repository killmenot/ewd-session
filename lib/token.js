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

function Token(documentStore, token, documentName) {
  this.documentName = documentName || DEFAULT_DOCUMENT_NAME;
  this.documentStore = documentStore;
  var tokenGlo = new documentStore.DocumentNode(this.documentName, ['sessionsByToken']);
  if (!token) token = uuid();
  this.value = token;
  this.data = tokenGlo.$(token);
}

var proto = Token.prototype;

Object.defineProperty(proto, 'session', require('./proto/token/session'));
Object.defineProperty(proto, 'sessionId', require('./proto/token/sessionId'));
Object.defineProperty(proto, 'exists', require('./proto/token/exists'));

proto.delete = require('./proto/token/delete');

module.exports = Token
