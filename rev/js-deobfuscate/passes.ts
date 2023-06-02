import traverse, { Node } from "@babel/traverse";
import { UnaryExpression, booleanLiteral, identifier, isArrayExpression, isIdentifier, isStringLiteral, isUnaryExpression, numericLiteral, stringLiteral } from "@babel/types";

/** Normalize the appearance of strings and remove \xNN and \uNNNN escapes where possible */
export function NormalizeStrings(node: Node) {
    traverse(node, {
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
    /* Collect aliases of the target function.
    TODO: this might be a bit safer if we specified a Path as a target
    rather than a name */
    traverse(node, {
        VariableDeclarator(path) {
            const id = path.node.id;
            const init = path.node.init;
            if (!isIdentifier(id) || !isIdentifier(init))
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
            if (!isIdentifier(callee))
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
                path.replaceWith(stringLiteral(impl.apply(null, funcArgValues)));
            }
        }
    });
    // Delete the now-useless aliasing assignments
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
        IfStatement(path) {
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

/** Replace !![] => true, ![] => false */
export function SimplifyBooleans(node: Node) {
    function isFalseExpression(node: UnaryExpression) {
        if (node.operator === "!" && isArrayExpression(node.argument) && node.argument.elements.length === 0) {
            return true;
        }
        return false;
    }

    traverse(node, {
        UnaryExpression(path) {
            if (isFalseExpression(path.node)) {
                path.replaceWith(booleanLiteral(false));
            } else if(path.node.operator === "!" && isUnaryExpression(path.node.argument) && isFalseExpression(path.node.argument)) {
                path.replaceWith(booleanLiteral(true));
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
    traverse(node, {
        MemberExpression(path) {
            if (path.node.computed) {
                const property = path.node.property;
                if (isStringLiteral(property) && property.value.match(/^[_A-Za-z$][_A-Za-z0-9$]*$/)) {
                    path.node.computed = false;
                    path.node.property = identifier(property.value);
                }
            }
        }
    });
}
