'use strict';

var symbolTableFactory = require('../../../lib/proto/symbolTable');
var dbMock = require('../mocks/db');
var documentStoreMock = require('../mocks/documentStore');
var documentNodeMock = require('../mocks/documentNode');

describe('unit/proto/symbolTable:', function () {
  var db;
  var symbolTable;
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {
      this.id = '123456';
      this.documentName = 'ewdSession';
    };
  });

  ['routineName', null].forEach(function (_routineName) {
    var routineName = _routineName || 'ewdSymbolTable';

    describe(_routineName || 'default routine name', function () {
      beforeEach(function () {
        db = dbMock.mock();
        symbolTable = symbolTableFactory(db, _routineName);

        session = new Session();
        session.documentStore = documentStoreMock.mock();
      });

      it('clear', function () {
        symbolTable.clear();

        expect(db.function).toHaveBeenCalledWith({
          function: 'clearSymbolTable^' + routineName
        });
      });

      it('save', function () {
        symbolTable.save(session);

        expect(db.function).toHaveBeenCalledWith({
          function: 'saveSymbolTable^' + routineName,
          arguments: ['^ewdSession("session",123456,"ewd_symbolTable")']
        });
      });

      it('restore', function () {
        symbolTable.restore(session);

        expect(db.function).toHaveBeenCalledWith({
          function: 'restoreSymbolTable^' + routineName,
          arguments: ['^ewdSession("session",123456,"ewd_symbolTable")']
        });
      });

      it('get', function () {
        var expected = {
          foo: 'bar'
        };

        var node = documentNodeMock.mock();
        node.getDocument.and.returnValue(expected);

        spyOn(session.documentStore, 'DocumentNode').and.returnValue(node);

        var actual = symbolTable.get(session);

        expect(session.documentStore.DocumentNode).toHaveBeenCalledWith('ewdSession', ['session', '123456', 'ewd_symbolTable']);
        expect(node.getDocument).toHaveBeenCalled();
        expect(actual).toEqual(expected);
      });

      it('setVar', function () {
        var expected = 'baz';

        db.function.and.returnValue({
          result: 'baz'
        });

        var actual = symbolTable.setVar('MName', 'bar');

        expect(actual).toBe(expected);
        expect(db.function).toHaveBeenCalledWith({
          function: 'setVar^' + routineName,
          arguments: ['MName', 'bar']
        });
      });

      it('getVar', function () {
        var expected = 'bar';

        db.function.and.returnValue({
          result: 'bar'
        });

        var actual = symbolTable.getVar('MName');

        expect(actual).toBe(expected);
        expect(db.function).toHaveBeenCalledWith({
          function: 'getVar^' + routineName,
          arguments: ['MName']
        });
      });

      it('killVar', function () {
        var expected = 'foo';

        db.function.and.returnValue({
          result: 'foo'
        });

        var actual = symbolTable.killVar('MName');

        expect(actual).toBe(expected);
        expect(db.function).toHaveBeenCalledWith({
          function: 'killVar^' + routineName,
          arguments: ['MName']
        });
      });
    });
  });
});
