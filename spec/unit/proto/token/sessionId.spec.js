'use strict';

var sessionId = require('../../../../lib/proto/token/sessionId');
var documentNodeMock = require('../../mocks/documentNode');

describe(' - unit/proto/token/sessionId:', function () {
  var Token;
  var token;

  beforeAll(function () {
    Token = function () {};

    var proto = Token.prototype;
    Object.defineProperty(proto, 'sessionId', sessionId);
  });

  beforeEach(function () {
    token = new Token();
    token.data = documentNodeMock.mock();
  });

  it('should return document node value', function () {
    token.data.value = 'foo';
    expect(token.sessionId).toBe('foo');
  });

  it('should set document node value', function () {
    token.sessionId = 'bar';
    expect(token.data.value).toBe('bar');
  });
});
