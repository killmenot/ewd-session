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

*/

var express = require('express');
var bodyParser = require('body-parser');
var qoper8 = require('ewd-qoper8');
var app = express();
app.use(bodyParser.json());

var q = new qoper8.masterProcess();

app.get('/qoper8/initiate', function (req, res) {
  var message = {
    type: 'initiate'
  };
  q.handleMessage(message, function(response) {
    res.send(response.message);
  });
});

app.post('/qoper8/login', function (req, res) {
  var message = {
    type: 'login',
    token: req.headers.authorization,
    credentials: req.body
  };
  q.handleMessage(message, function(response) {
    if (response.message.error) {
      var status = 400;
      if (response.message.status && response.message.status.code) {
        status = response.message.status.code;
      }
      res.status(status).send({error: response.message.error});
    }
    else {
      res.send(response.message);
    }
  });
});

q.on('started', function() {
  this.worker.module = 'ewd-session/examples/cache-module1';
  app.listen(8080);
});

q.start();

