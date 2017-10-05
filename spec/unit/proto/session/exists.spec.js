'use strict';

var exists = require('../../../../lib/proto/session/exists');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/exists:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'exists', exists);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return existence value', function () {
    session.data.exists = false;
    expect(session.exists).toBeFalsy();
  });
});
