'use strict';

module.exports = {
  mock: function () {
    var db = {
      function: jasmine.createSpy()
    };

    return db;
  }
};
