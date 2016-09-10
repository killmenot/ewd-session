ewdSymbolTable ; ewd-globals-session functions for symbol table management
 ;
 ; ----------------------------------------------------------------------------
 ; | ewd-session: Session management using ewd-document-store                 |
 ; |                                                                          |
 ; | Copyright (c) 2016 M/Gateway Developments Ltd,                           |
 ; | Reigate, Surrey UK.                                                      |
 ; | All rights reserved.                                                     |
 ; |                                                                          |
 ; | http://www.mgateway.com                                                  |
 ; | Email: rtweed@mgateway.com                                               |
 ; |                                                                          |
 ; |                                                                          |
 ; | Licensed under the Apache License, Version 2.0 (the "License");          |
 ; | you may not use this file except in compliance with the License.         |
 ; | You may obtain a copy of the License at                                  |
 ; |                                                                          |
 ; |     http://www.apache.org/licenses/LICENSE-2.0                           |
 ; |                                                                          |
 ; | Unless required by applicable law or agreed to in writing, software      |
 ; | distributed under the License is distributed on an "AS IS" BASIS,        |
 ; | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
 ; | See the License for the specific language governing permissions and      |
 ; |  limitations under the License.                                          |
 ; ----------------------------------------------------------------------------
 ;
 ; Build 1: 3 March 2016
 ;
 ;QUIT
 ;
clearSymbolTable() ;
 k
 QUIT 1
 ;
saveSymbolTable(%zzg) ;
 ; Save Symbol Table to specified global node (%zzg)
 ; %zzg is of form "^gloName(""sub1"",""sub2"")"
 ; %zzg must specify at least one subscript
 ;
 k @%zzg
 i $zv["GT.M" zshow "v":@%zzg QUIT 1
 ;
 QUIT $zu(160,1,%zzg)
 ;
restoreSymbolTable(gloRef) ;
 ; Restore Symbol Table from specified global node
 ; gloRef is of form "^gloName(""sub1"",""sub2"")"

 ; gloRef must specify at least one subscript
 ;
 k (gloRef)
 i $zv["GT.M" d  quit 1
 . n i f i=0:0 s i=$o(@gloRef@("V",i)) q:'i  s @^(i)
 ;
 QUIT $zu(160,0,gloRef)
 ;
getSessionSymbolTable(sessid) ;
 ;
 n gloRef
 ;
 s gloRef="^%zewdSession(""session"","_sessid_",""ewd_symbolTable"")"
 i $$restoreSymbolTable(gloRef)
 k %zzg
 QUIT "ok"
 ;
