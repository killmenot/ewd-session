'use strict';

module.exports = {
  mock: function () {
    var documentNode = {
      $: jasmine.createSpy(),
      delete: jasmine.createSpy(),
      getDocument: jasmine.createSpy()
    };

    return documentNode;
  }
};
