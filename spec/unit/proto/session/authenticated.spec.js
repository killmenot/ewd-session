'use strict';

var authenticated = require('../../../../lib/proto/session/authenticated');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/authenticated:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'authenticated', authenticated);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return authenticated value', function () {
    var node = {
      value: true
    };
    session.data.$.and.returnValue(node);

    var actual = session.authenticated;

    expect(actual).toBeTruthy();
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'authenticated']);
  });

  it('should set authenticated value', function () {
    var node = {};
    session.data.$.and.returnValue(node);

    session.authenticated = false;

    expect(node.value).toBeFalsy();
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'authenticated']);
  });
});
