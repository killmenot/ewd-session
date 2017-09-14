'use strict';

module.exports = {
  mock: function () {
    var documentNode = {
      $: jasmine.createSpy(),
      delete: jasmine.createSpy(),
      getDocument: jasmine.createSpy(),
      setDocument: jasmine.createSpy(),
      increment: jasmine.createSpy()
    };

    return documentNode;
  }
};
