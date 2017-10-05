'use strict';

var socketId = require('../../../../lib/proto/session/socketId');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/socketId:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'socketId', socketId);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return socketId value', function () {
    var expected = '/#yf_vd-S9Q7e-LX28AAAS';
    var node = {
      value: '/#yf_vd-S9Q7e-LX28AAAS'
    };
    session.data.$.and.returnValue(node);

    var actual = session.socketId;

    expect(actual).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'socketId']);
  });

  it('should set socketId value', function () {
    var expected = '/#yf_vd-J9Q5e-LX27AAAS';
    var node = {};
    session.data.$.and.returnValue(node);

    session.socketId = '/#yf_vd-J9Q5e-LX27AAAS';

    expect(node.value).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'socketId']);
  });
});
