'use strict';

var expiryTime = require('../../../../lib/proto/session/expiryTime');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/expiryTime:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'expiryTime', expiryTime);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return expiryTime value', function () {
    var expected = 3600;
    var node = {
      value: '3600'
    };
    session.data.$.and.returnValue(node);

    var actual = session.expiryTime;

    expect(actual).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'expiry']);
  });

  it('should set expiryTime value', function () {
    var expected = 3600;
    var node = {};
    session.data.$.and.returnValue(node);

    session.expiryTime = 3600;

    expect(node.value).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'expiry']);
  });
});
