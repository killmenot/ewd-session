'use strict';

var ipAddress = require('../../../../lib/proto/session/ipAddress');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/ipAddress:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'ipAddress', ipAddress);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return ipAddress value', function () {
    var expected = '192.168.1.12';
    var node = {
      value: '192.168.1.12'
    };
    session.data.$.and.returnValue(node);

    var actual = session.ipAddress;

    expect(actual).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'ipAddress']);
  });

  it('should set ipAddress value', function () {
    var expected = '192.168.1.12';
    var node = {};
    session.data.$.and.returnValue(node);

    session.ipAddress = '192.168.1.12';

    expect(node.value).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'ipAddress']);
  });
});
