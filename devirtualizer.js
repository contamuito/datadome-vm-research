#!/usr/bin/env node
/**
 * DataDome VM Devirtualizer & AST Reconstructor
 *
 * Slices the 117 internal VM closures and performs symbolic decompilation
 * from bytecode assembly back into clean, readable JavaScript functions.
 *
 * Usage:
 *   node devirtualizer.js
 *   node devirtualizer.js --fn fn_001
 *   node devirtualizer.js --out-dir ./devirtualized
 */

const fs = require('fs');
const path = require('path');

class VMDevirtualizer {
    constructor(disasmPath, callGraphPath) {
        this.disasmLines = fs.readFileSync(disasmPath, 'utf8').split('\n');
        this.functions = JSON.parse(fs.readFileSync(callGraphPath, 'utf8'));
        this.labelMap = new Map();
        this.buildLabelMap();
    }

    buildLabelMap() {
        for (let i = 0; i < this.disasmLines.length; i++) {
            const line = this.disasmLines[i].trim();
            const m = line.match(/^(L_[0-9a-fA-F]+):/);
            if (m) {
                this.labelMap.set(m[1], i);
            }
        }
    }

    decompileFunction(fnMeta) {
        const startLine = this.labelMap.get(fnMeta.entry_label);
        const endLine = fnMeta.exit_label ? this.labelMap.get(fnMeta.exit_label) : null;
        if (startLine === undefined) return '// Error: Entry label not found';

        const lines = this.disasmLines.slice(startLine, endLine || (startLine + fnMeta.instructions_count));
        
        const stack = [];
        const statements = [];
        const localsDeclared = new Set();
        const regsDeclared = new Set();

        const pop = () => (stack.length > 0 ? stack.pop() : 'undefined');
        const push = (expr) => stack.push(expr);

        for (let rawLine of lines) {
            rawLine = rawLine.trim();
            if (!rawLine || rawLine.startsWith(';')) continue;
            if (rawLine.endsWith(':')) {
                statements.push(`\n  // Label ${rawLine}`);
                continue;
            }

            const parts = rawLine.split(/\s+/);
            const opIdx = parts.findIndex(p => /^[A-Z0-9_]+$/.test(p));
            if (opIdx === -1) continue;

            const op = parts[opIdx];
            const argsStr = parts.slice(opIdx + 1).join(' ');
            const args = argsStr.split(',').map(s => s.trim());

            switch (op) {
                case 'PUSH_IMM':
                    push(argsStr);
                    break;

                case 'PUSH_REG': {
                    const r = `r${args[0]}`;
                    regsDeclared.add(r);
                    push(r);
                    break;
                }

                case 'POP_REG':
                case 'POP_REG_LR': {
                    const r = `r${args[0]}`;
                    regsDeclared.add(r);
                    statements.push(`  ${r} = ${pop()};`);
                    break;
                }

                case 'POP_REG_IMM': {
                    const r = `r${args[0]}`;
                    regsDeclared.add(r);
                    statements.push(`  ${r} = ${args[1]};`);
                    break;
                }

                case 'PUSH_FRAME': {
                    const loc = `local_${args[0]}`;
                    localsDeclared.add(loc);
                    push(loc);
                    break;
                }

                case 'STORE_FRAME':
                case 'POP_FRAME_LR': {
                    const loc = `local_${args[0]}`;
                    localsDeclared.add(loc);
                    statements.push(`  ${loc} = ${pop()};`);
                    break;
                }

                case 'PUSH_FRAME_IMM': {
                    const loc = `local_${args[0]}`;
                    localsDeclared.add(loc);
                    push(loc);
                    push(args[1]);
                    break;
                }

                case 'PUSH_WINDOW':
                    push('window');
                    break;

                case 'PUSH_REG_IMM': {
                    const r = `r${args[0]}`;
                    regsDeclared.add(r);
                    push(r);
                    push(args[1]);
                    break;
                }

                case 'PUSH_R2': {
                    regsDeclared.add(`r${args[0]}`);
                    regsDeclared.add(`r${args[1]}`);
                    push(`r${args[0]}`);
                    push(`r${args[1]}`);
                    break;
                }

                case 'PUSH_R3': {
                    regsDeclared.add(`r${args[0]}`);
                    regsDeclared.add(`r${args[1]}`);
                    regsDeclared.add(`r${args[2]}`);
                    push(`r${args[0]}`);
                    push(`r${args[1]}`);
                    push(`r${args[2]}`);
                    break;
                }

                case 'PUSH_R2_IMM': {
                    regsDeclared.add(`r${args[0]}`);
                    regsDeclared.add(`r${args[1]}`);
                    push(`r${args[0]}`);
                    push(`r${args[1]}`);
                    push(args[2]);
                    break;
                }

                case 'PUSH_REG2_GET': {
                    regsDeclared.add(`r${args[0]}`);
                    regsDeclared.add(`r${args[1]}`);
                    push(`r${args[0]}[r${args[1]}]`);
                    break;
                }

                case 'GET_PROP_IMM': {
                    const obj = pop();
                    push(`${obj}[${argsStr}]`);
                    break;
                }

                case 'GET': {
                    const prop = pop();
                    const obj = pop();
                    push(`${obj}[${prop}]`);
                    break;
                }

                case 'GET_AND_MASK': {
                    const mask = pop();
                    const idx = pop();
                    const obj = pop();
                    push(`${obj}[(${idx} & ${mask})]`);
                    break;
                }

                case 'SET': {
                    const val = pop();
                    const prop = pop();
                    const obj = pop();
                    statements.push(`  ${obj}[${prop}] = ${val};`);
                    break;
                }

                case 'REG_SET': {
                    const val = pop();
                    const r1 = `r${args[0]}`;
                    const r2 = `r${args[1]}`;
                    regsDeclared.add(r1);
                    regsDeclared.add(r2);
                    statements.push(`  ${r1}[${r2}] = ${val};`);
                    break;
                }

                case 'ADD': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} + ${b})`);
                    break;
                }

                case 'SUB': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} - ${b})`);
                    break;
                }

                case 'MUL': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} * ${b})`);
                    break;
                }

                case 'MOD': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} % ${b})`);
                    break;
                }

                case 'MOD_IMM': {
                    const a = pop();
                    push(`(${a} % ${args[0]})`);
                    break;
                }

                case 'AND': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} & ${b})`);
                    break;
                }

                case 'AND_IMM': {
                    const a = pop();
                    push(`(${a} & ${args[0]})`);
                    break;
                }

                case 'OR': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} | ${b})`);
                    break;
                }

                case 'XOR': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} ^ ${b})`);
                    break;
                }

                case 'XOR_IMM': {
                    const a = pop();
                    push(`(${a} ^ ${args[0]})`);
                    break;
                }

                case 'SHL': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} << ${b})`);
                    break;
                }

                case 'SHL_IMM': {
                    const a = pop();
                    push(`(${a} << ${args[0]})`);
                    break;
                }

                case 'SHR': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} >> ${b})`);
                    break;
                }

                case 'SHR_IMM': {
                    const a = pop();
                    push(`(${a} >> ${args[0]})`);
                    break;
                }

                case 'USHR': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} >>> ${b})`);
                    break;
                }

                case 'EQ': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} == ${b})`);
                    break;
                }

                case 'SEQ': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} === ${b})`);
                    break;
                }

                case 'LT': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} < ${b})`);
                    break;
                }

                case 'GT': {
                    const b = pop();
                    const a = pop();
                    push(`(${a} > ${b})`);
                    break;
                }

                case 'NOT': {
                    const a = pop();
                    push(`(!${a})`);
                    break;
                }

                case 'TYPEOF': {
                    const a = pop();
                    push(`(typeof ${a})`);
                    break;
                }

                case 'CALL_U8': {
                    const argc = parseInt(args[0]) || 0;
                    const callArgs = [];
                    for (let i = 0; i < argc; i++) callArgs.unshift(pop());
                    const target = pop();
                    const thisCtx = pop();
                    push(`${target}(${callArgs.join(', ')})`);
                    break;
                }

                case 'NEW_U8': {
                    const argc = parseInt(args[0]) || 0;
                    const ctorArgs = [];
                    for (let i = 0; i < argc; i++) ctorArgs.unshift(pop());
                    const ctor = pop();
                    push(`new ${ctor}(${ctorArgs.join(', ')})`);
                    break;
                }

                case 'MAKE_ARRAY': {
                    const count = parseInt(args[0]) || 0;
                    const items = [];
                    for (let i = 0; i < count; i++) items.unshift(pop());
                    push(`[${items.join(', ')}]`);
                    break;
                }

                case 'RET':
                    statements.push(`  return ${pop()};`);
                    break;

                case 'RET_LOCAL':
                    statements.push(`  return local_${args[0]};`);
                    break;

                case 'JZ':
                    statements.push(`  if (!${pop()}) goto ${args[0]};`);
                    break;

                case 'JMP_FWD':
                case 'JMP_BACK':
                    statements.push(`  goto ${args[0]};`);
                    break;

                default:
                    break;
            }
        }

        // Build function signature
        const paramNames = Array.from({ length: fnMeta.locals_count }, (_, i) => `local_${i}`);
        const header = `/**\n * Decompiled Function: ${fnMeta.id}\n * Entry: ${fnMeta.entry_label} | Exit: ${fnMeta.exit_label || 'EOF'}\n * Captures: [${fnMeta.captures.join(', ')}]\n * Strings: ${JSON.stringify(fnMeta.referenced_strings)}\n */\nfunction ${fnMeta.id}(${paramNames.join(', ')}) {`;
        const declarations = [];
        if (regsDeclared.size > 0) {
            declarations.push(`  let ${Array.from(regsDeclared).join(', ')};`);
        }
        
        return `${header}\n${declarations.join('\n')}\n${statements.join('\n')}\n}`;
    }

    decompileAll(outDir) {
        if (!fs.existsSync(outDir)) {
            fs.mkdirSync(outDir, { recursive: true });
        }

        console.log(`Decompiling ${this.functions.length} functions into ${outDir}...`);
        for (const fn of this.functions) {
            const code = this.decompileFunction(fn);
            const filePath = path.join(outDir, `${fn.id}.js`);
            fs.writeFileSync(filePath, code, 'utf8');
        }
        console.log(`Finished decompilation of all ${this.functions.length} functions.`);
    }
}

function main() {
    const args = process.argv.slice(2);
    const disasmPath = path.join(__dirname, 'out_improved.txt');
    const callGraphPath = path.join(__dirname, 'call_graph.json');

    if (!fs.existsSync(disasmPath) || !fs.existsSync(callGraphPath)) {
        console.error('Error: out_improved.txt or call_graph.json missing. Run disasm_improved.js and callgraph_extractor.py first.');
        process.exit(1);
    }

    const devirt = new VMDevirtualizer(disasmPath, callGraphPath);

    const fnIdx = args.indexOf('--fn');
    if (fnIdx !== -1 && args[fnIdx + 1]) {
        const targetId = args[fnIdx + 1];
        const fn = devirt.functions.find(f => f.id === targetId || f.entry_label === targetId);
        if (!fn) {
            console.error(`Function ${targetId} not found.`);
            process.exit(1);
        }
        console.log(devirt.decompileFunction(fn));
        return;
    }

    const outDir = path.join(__dirname, 'devirtualized');
    devirt.decompileAll(outDir);
}

if (require.main === module) {
    main();
}
