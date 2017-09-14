'use strict';

var application = require('../../../../lib/proto/session/application');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/application:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'application', application);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return application name', function () {
    var expected = 'baz';
    session.data.$.and.returnValue({
      value: 'baz'
    });

    var actual = session.application;

    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'application']);
    expect(actual).toBe(expected);
  });
});
