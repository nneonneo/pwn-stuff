import generate from "@babel/generator";
import { parse } from "@babel/parser";
import * as passes from '../passes.js';

const ast = parse(`
function hi(_0x254361) {
    var _0x67ba60 = {
        'Elavc': function (_0x344803, _0x145d96) {
            return _0x344803 === _0x145d96;
        },
        'hDlnJ': 'Hello\x20World!',
        'csStW': 'ahaw?'
    };
    if (_0x67ba60['Elavc'](_0x254361, 0x3)) {
        console['log'](_0x67ba60['hDlnJ']);
    } else if (_0x67ba60['Elavc'](_0x254361, 0x5)) {
        console['log'](_0x67ba60['csStW']);
    }
}
hi();
`);

// Passes go here
passes.NormalizeStrings(ast);
passes.ConvertToDotNotation(ast);
passes.NormalizeNumbers(ast);
passes.InlineTrivialOpObjects(ast);
passes.RenameVariables(ast, (name) => name.startsWith("_0x"));

const output = generate.default(ast).code;
console.log(output);
