'use strict';

var allowService = require('../../../../lib/proto/session/allowService');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/allowService:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {
      this.allowService = allowService;
    };
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should not set value', function () {
    session.allowService();
    expect(session.data.$).not.toHaveBeenCalled();
  });

  it('should set value', function () {
    var node = {};
    session.data.$.and.returnValue(node);

    session.allowService('foo');

    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'services_allowed', 'foo']);
    expect(node.value).toBeTruthy();
  });
});
