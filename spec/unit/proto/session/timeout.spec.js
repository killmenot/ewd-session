'use strict';

var timeout = require('../../../../lib/proto/session/timeout');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/timeout:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'timeout', timeout);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return timeout value', function () {
    var expected = 30000;
    var node = {
      value: '30000'
    };
    session.data.$.and.returnValue(node);

    var actual = session.timeout;

    expect(actual).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'timeout']);
  });

  it('should set timeout value', function () {
    var expected = 30000;
    var node = {};
    session.data.$.and.returnValue(node);

    session.timeout = 30000;

    expect(node.value).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'timeout']);
  });
});
