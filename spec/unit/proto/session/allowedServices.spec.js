'use strict';

var allowedServices = require('../../../../lib/proto/session/allowedServices');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/allowedServices:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'allowedServices', allowedServices);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return allowed services', function () {
    var expected = {
      foo: true,
      bar: false
    };
    var node = documentNodeMock.mock();
    node.getDocument.and.returnValue(expected);

    session.data.$.and.returnValue(node);

    var actual = session.allowedServices;

    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'services_allowed']);
    expect(actual).toBe(expected);
  });
});
