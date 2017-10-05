'use strict';

require('dotenv').config();

var sessions = require('../../../');
var connectCacheTo = require('ewd-qoper8-cache');

module.exports = function () {

  this.on('dbOpened', function (status) {
    console.log('Cache was opened by worker ' + process.pid + ': status = ' + JSON.stringify(status));
  });

  this.on('start', function () {
    if (this.log) {
      console.log('Worker process ' + process.pid + ' starting...');
    }

    connectCacheTo(this, {
      path: process.env.CACHE_MGR_PATH,
      username: process.env.CACHE_USERNAME,
      password: process.env.CACHE_PASSWORD,
      namespace: process.env.CACHE_NAMESPACE
    });

    sessions.init(this.documentStore);
    sessions.garbageCollector(this, 5);
  });

  this.on('stop', function () {
    if (this.log) {
      console.log('Worker process ' + process.pid + ' stopping...');
    }
  });

};
