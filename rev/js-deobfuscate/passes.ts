import generate from "@babel/generator";
import traverse, { Binding, Node, NodePath, Scope } from "@babel/traverse";
import * as t from "@babel/types";

function dump(node: Node): string {
    return node.type + "(" + generate(node).code + ")";
}

/** Normalize the appearance of strings, collapse string concatenation, and remove \xNN and \uNNNN escapes where possible */
export function NormalizeStrings(node: Node) {
    traverse(node, {
        BinaryExpression: {
            exit(path) {
                if (path.node.operator === "+" && t.isStringLiteral(path.node.left) && t.isStringLiteral(path.node.right)) {
                    path.replaceWith(t.stringLiteral(path.node.left.value + path.node.right.value));
                }
            }
        },
        StringLiteral(path) {
            if (path.node.extra && path.node.extra.raw) {
                delete path.node.extra.raw;
            }
        }
    });
}

/** Inline all calls to the given function using the given implementation.
 * For example, you could pass the string obfuscation lookup function, after
 * copying the relevant string array decryption code. */
export function InlineFunction(node: Node, name: String, impl: Function) {
    let targetPaths: NodePath[] = [];

    traverse(node, {
        FunctionDeclaration(path) {
            const id = path.node.id;

            // path.scope should be FunctionDeclaration
            // parent should be the top-level program
            let parent = path.scope.parent;
            if (parent && parent.parent) {
                // this is a nested function of some kind - ignore
                return;
            }
            if (t.isIdentifier(id) && id.name === name) {
                targetPaths.push(path);
                path.setData("alias", name);
            }
        }
    });

    if (targetPaths.length === 0) {
        console.error("Failed to find function declaration for " + name);
        return;
    }
    if (targetPaths.length > 1) {
        console.error("Too many function declarations for " + name + "!");
        return;
    }

    /* Collect aliases of the target function. */
    traverse(node, {
        VariableDeclarator(path) {
            const id = path.node.id;
            const init = path.node.init;
            if (!t.isIdentifier(id) || !t.isIdentifier(init))
                return;

            const initBinding = path.scope.getBinding(init.name);
            if (!initBinding)
                return;

            path.setData("alias", initBinding.path.getData("alias", init.name));
        }
    });
    traverse(node, {
        CallExpression(path) {
            const callee = path.node.callee;
            if (!t.isIdentifier(callee))
                return;

            const binding = path.scope.getBinding(callee.name);
            if (!binding)
                return;

            const alias = binding.path.getData("alias");
            if (callee.name === name || alias === name) {
                let funcArgs = path.get("arguments").map((argPath) => argPath.evaluate());
                if (!funcArgs.every((result) => result.confident)) {
                    return;
                }
                let funcArgValues = funcArgs.map((result) => result.value);
                console.log(callee.name, alias, funcArgValues);
                path.replaceWith(t.stringLiteral(impl.apply(null, funcArgValues)));
            }
        }
    });

    // Delete the now-useless aliasing assignments
    targetPaths[0].remove();
    traverse(node, {
        VariableDeclarator(path) {
            const alias = path.getData("alias");
            if (alias === name) {
                path.remove();
            }
        }
    });
}

/** Simplify branches with a constant predicate */
export function SimplifyConstantBranches(node: Node) {
    traverse(node, {
        Conditional(path) {
            let test = path.get("test").evaluateTruthy();
            if (test === undefined)
                return;
            if (test) {
                path.replaceWith(path.get("consequent"));
            } else {
                let alternate = path.get("alternate");
                if (alternate.node) {
                    path.replaceWith(alternate.node);
                } else {
                    path.remove();
                }
            }
        }
    });
}

/** Undo obfuscator.io's "control flow flattening", which is really just moving
 * certain trivial operations and strings into a local object variable.
 * You'll probably want to inline the string encryption routines first, then
 * run SimplifyConstantBranches afterwards to simplify inlined branch tests.
 */
export function InlineTrivialOpObjects(node: Node) {
    type OpValue = t.StringLiteral | t.FunctionExpression;
    type OpObject = { [key: string]: OpValue };
    function parseTrivialOpObject(node: t.ObjectExpression): OpObject | undefined {
        let result = {};

        for (let prop of node.properties) {
            if (!t.isObjectProperty(prop)) {
                // so far, the obfuscator does not use member functions; the
                // functions it does contain are of the form "asdfg": function(...) {...}
                return;
            }

            let key: string;
            if (t.isIdentifier(prop.key)) {
                key = prop.key.name;
            } else if (t.isStringLiteral(prop.key)) {
                key = prop.key.value;
            } else {
                // so far, keys on these are always constants
                return;
            }
            if (key.length !== 5) {
                // XXX this is making a serious assumption about the obfuscator being used!
                // this particular obfuscation always seems to use 5-character keys...
                return;
            }

            if (t.isStringLiteral(prop.value)) {
                result[key] = prop.value;
            } else if (t.isFunctionExpression(prop.value)) {
                result[key] = prop.value;
            } else {
                return;
            }
        }
        if (node.properties.length >= 1) {
            return result;
        }
    }

    function getObjectBinding(scope: Scope, node: t.Expression): Binding | undefined {
        if (!t.isIdentifier(node)) {
            return;
        }
        return scope.getBinding(node.name);
    }

    function getPropertyName(node: t.MemberExpression): string | undefined {
        if (t.isIdentifier(node.property)) {
            return node.property.name;
        } else if (t.isStringLiteral(node.property)) {
            return node.property.value;
        }
    }

    function getOpRef(scope: Scope, node: t.MemberExpression): OpValue | undefined {
        const binding = getObjectBinding(scope, node.object);
        if (!binding) {
            return;
        }

        const obj: OpObject | undefined = binding.path.getData("trivial_op");
        if (!obj) {
            return;
        }

        const key = getPropertyName(node);
        if (!key) {
            return;
        }

        return obj[key];
    }

    function isExpressionArray(arr: any[]): arr is t.Expression[] {
        return arr.every((obj) => t.isExpression(obj));
    }

    function substitute(path: NodePath<t.CallExpression>, func: t.FunctionExpression, args: t.Expression[]): boolean {
        if (func.body.body.length != 1) {
            console.log(`function ${dump(func)} is not simple!`);
            return false;
        }

        let argMap: { [key: string]: t.Expression } = {};
        for (var i = 0; i < func.params.length; i++) {
            const param = func.params[i];
            if (!t.isIdentifier(param)) {
                console.log(`function ${dump(func)}: arguments are not simple`);
                return false;
            }
            argMap[param.name] = args[i] || t.identifier("undefined");
        }

        // TODO(nneonneo): maybe we can relax this
        const bodyStatement = func.body.body[0];
        if (!t.isReturnStatement(bodyStatement)) {
            console.log(`function ${dump(func)} is not a single return statement!`);
            return false;
        }

        const bodyExpr = bodyStatement.argument;
        if (!bodyExpr) {
            path.replaceWith(t.identifier("undefined"));
            return true;
        }

        let newExpr = t.cloneNode(bodyExpr);
        path.replaceWith(newExpr);
        traverse(newExpr, {
            Identifier(npath) {
                if (npath.node.name in argMap) {
                    // XXX(nneonneo) this is a horrible hack.
                    // If we attempt to do the replacement here, Babel explodes.
                    // This might be due to the fact that we're inside an active traversal.
                    npath.setData("__replaceMe", t.cloneNode(argMap[npath.node.name]));
                }
            }
        }, path.scope, undefined, path.parentPath);
        return true;
    }

    // Find all potential trivial op objects
    traverse(node, {
        VariableDeclarator(path) {
            const id = path.node.id;
            const init = path.node.init;
            if (!t.isIdentifier(id) || !t.isObjectExpression(init))
                return;

            let obj = parseTrivialOpObject(init);
            if (obj) {
                path.setData("trivial_op", obj);
                path.setData("trivial_op_clean", true);
            }
        }
    });

    // Validation pass to make sure we aren't doing anything weird with this object
    traverse(node, {
        VariableDeclarator(path) {
            if (path.getData("trivial_op")) {
                path.skip();
            }
        },
        MemberExpression(path) {
            const binding = getObjectBinding(path.scope, path.node.object);
            if (!binding) {
                return;
            }

            const obj: OpObject | undefined = binding.path.getData("trivial_op");
            if (!obj) {
                return;
            }

            const key = getPropertyName(path.node);
            if (!key) {
                console.log(`object ${binding.identifier.name} used with computed member expression ${dump(path.node)}; not trivial`);
                binding.path.setData("trivial_op_clean", false);
            } else if (path.parentPath.isAssignmentExpression({ left: path.node })) {
                console.log(`property ${dump(path.node)} is being set in ${dump(path.parent)}!`);
                delete obj[key];
                binding.path.setData("trivial_op_clean", false);
            }
            path.skip();
        },
        Identifier(path) {
            const binding = getObjectBinding(path.scope, path.node);
            if (!binding) {
                return;
            }

            const obj: OpObject | undefined = binding.path.getData("trivial_op");
            if (!obj) {
                return;
            }

            const parent = path.parent;
            console.log(`object ${path.node.name} used in non-member expression ${dump(parent)}; not trivial`);
            binding.path.setData("trivial_op_clean", false);
        }
    });

    // Main replacement pass
    traverse(node, {
        CallExpression(path) {
            const callee = path.node.callee;
            if (!t.isMemberExpression(callee)) {
                return;
            }
            const opRef = getOpRef(path.scope, callee);
            if (!opRef) {
                return;
            }
            if (t.isFunctionExpression(opRef) && isExpressionArray(path.node.arguments)) {
                const result = substitute(path, opRef, path.node.arguments);
                if (result) {
                    return;
                }
            }

            console.log(`unable to substitute call ${dump(path.node)}!`);
            const binding = getObjectBinding(path.scope, callee.object);
            if (binding) {
                binding.path.setData("trivial_op_clean", false);
            }
        },
        Identifier(path) {
            const obj = path.getData("__replaceMe");
            if (obj) {
                path.setData("__replaceMe", undefined);
                path.replaceWith(obj);
            }
        },
        MemberExpression(path) {
            if (path.parentPath.isCallExpression({ callee: path.node })) {
                return;
            }
            const opRef = getOpRef(path.scope, path.node);
            if (!opRef) {
                return;
            }
            if (t.isStringLiteral(opRef)) {
                path.replaceWith(t.cloneNode(opRef));
                return;
            }

            console.log(`unable to substitute string ${dump(path.node)}!`);
            const binding = getObjectBinding(path.scope, path.node.object);
            if (binding) {
                binding.path.setData("trivial_op_clean", false);
            }
        }
    });

    // Delete unused trivial op declarators
    traverse(node, {
        VariableDeclarator(path) {
            if (path.getData("trivial_op") && path.getData("trivial_op_clean")) {
                path.remove();
            }
        }
    });
}

/** Replace !![] => true, ![] => false */
export function SimplifyBooleans(node: Node) {
    function isFalseExpression(node: t.UnaryExpression) {
        if (node.operator === "!" && t.isArrayExpression(node.argument) && node.argument.elements.length === 0) {
            return true;
        }
        return false;
    }

    traverse(node, {
        UnaryExpression(path) {
            if (isFalseExpression(path.node)) {
                path.replaceWith(t.booleanLiteral(false));
            } else if (path.node.operator === "!" && t.isUnaryExpression(path.node.argument) && isFalseExpression(path.node.argument)) {
                path.replaceWith(t.booleanLiteral(true));
            }
        }
    });
}

/** Normalize the appearance of numbers, transforming hexadecimal integers into decimal */
export function NormalizeNumbers(node: Node) {
    traverse(node, {
        NumericLiteral(path) {
            if (path.node.extra && path.node.extra.raw) {
                delete path.node.extra.raw;
            }
        }
    });
}

/** Convert property accesses E['X'] to E.X notation where possible */
export function ConvertToDotNotation(node: Node) {
    function makeIdentifier(node: Node): t.Identifier | undefined {
        if (t.isStringLiteral(node) && node.value.match(/^[_A-Za-z$][_A-Za-z0-9$]*$/)) {
            return t.identifier(node.value);
        }
    }

    traverse(node, {
        ObjectMember(path) {
            const newId = makeIdentifier(path.node.key);
            if (newId) {
                path.node.computed = false;
                path.node.key = newId;
            }
        },
        ClassMethod(path) {
            const newId = makeIdentifier(path.node.key);
            if (newId) {
                path.node.computed = false;
                path.node.key = newId;
            }
        },
        MemberExpression(path) {
            if (path.node.computed) {
                const newId = makeIdentifier(path.node.property);
                if (newId) {
                    path.node.computed = false;
                    path.node.property = newId;
                }
            }
        }
    });
}

/** Heuristically rename variables to be more useful.
 * Parameters => p1, p2, p3, ...
 * Local variables => v1, v2, v3, ...
 * Loop variables => i, j, k, i4, i5, ...
 * 
 * shouldRename is a callback that determines if a variable should be renamed:
 *  for example, if it is below a certain length, or if it starts with _0x, etc.
 */
export function RenameVariables(node: Node, shouldRename: (ident: string) => boolean) {
    function renameVariable(path: NodePath, oldName: string, fixedNames: string[], prefixName: string, prefixStart: number) {
        if (!shouldRename(oldName)) {
            return;
        }
        for (let newName of fixedNames) {
            if (!path.scope.hasBinding(newName)) {
                path.scope.rename(oldName, newName);
                return;
            }
        }
        while (true) {
            let newName = prefixName + prefixStart;
            if (!path.scope.hasBinding(newName)) {
                path.scope.rename(oldName, newName);
                return;
            }
            prefixStart++;
        }
    }

    traverse(node, {
        Function(path) {
            for (let param of path.node.params) {
                if (t.isIdentifier(param)) {
                    renameVariable(path, param.name, [], "p", 1);
                }
                /* TODO(nneonneo): patterns? */
            }
        },
        VariableDeclarator(path) {
            const id = path.node.id;
            if (!t.isIdentifier(id))
                return;

            let parent = path.parentPath;
            if (parent?.isVariableDeclaration()) {
                parent = parent?.parentPath;
            }

            if (parent && t.isFor(parent)) {
                renameVariable(path, id.name, ["i", "j", "k"], "i", 4);
            } else {
                renameVariable(path, id.name, [], "v", 1);
            }
        }
    });
}
