'use strict';

var DocumentNode = function (documentStore, documentName, path) {
  this.documentStore = documentStore;
  this.documentName = documentName;
  this.path = path;
};

var DocumentStore = function () {
  this.DocumentNode = DocumentNode.bind(undefined, this);
};

module.exports = {
  mock: function () {
    return new DocumentStore();
  }
};
