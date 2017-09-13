'use strict';

module.exports = {
  mock: function () {
    var documentNode = {
      $: jasmine.createSpy(),
      delete: jasmine.createSpy()
    };

    return documentNode;
  }
};
