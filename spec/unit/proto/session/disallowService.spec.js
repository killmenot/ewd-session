'use strict';

var disallowService = require('../../../../lib/proto/session/disallowService');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/disallowService:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {
      this.disallowService = disallowService;
    };
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should not set value', function () {
    session.disallowService();
    expect(session.data.$).not.toHaveBeenCalled();
  });

  it('should set value', function () {
    var node = {};
    session.data.$.and.returnValue(node);

    session.disallowService('bar');

    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'services_allowed', 'bar']);
    expect(node.value).toBeFalsy();
  });
});
