// Taint analysis estático do app Aquenda (React Native + TypeScript).
//
// Segue o dado sensível (agenda de hormônio, consultas, PIN, posição) desde a fonte (SQLite,
// armazenamento seguro, formulário, GPS) até as saídas inseguras (rede, log, links, área de
// transferência, armazenamento sem cifra, notificação na tela bloqueada).
//
// Como funciona:
// - O TypeChecker do TypeScript resolve cada nome ao mesmo símbolo em qualquer arquivo.
// - Dentro da função, o dado anda por variáveis, desestruturação, objetos (um nível de campo),
//   template strings, operadores, callbacks (.map, .then) e estado do React (useState).
// - Entre funções, cada função ganha um RESUMO: quais parâmetros (e quais campos deles) chegam
//   ao retorno e a cada saída insegura. Cada chamada aplica o resumo com os próprios argumentos.
//   Assim, um utilitário usado em vários lugares não mistura o dado de uma tela com o de outra.
// - Repete até nada mudar (ponto fixo).
//
// Uso: node taint_ts/analisar.mjs <pasta-do-app> [--politica arquivo.json] [--saida relatorio.json]

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const aqui = path.dirname(fileURLToPath(import.meta.url));
const FANTASMA = "§"; // rótulo de parâmetro ainda não resolvido: §<funcao>:<indice>[~<campo>]
const CAMPO = "~";

// ------------------------------------------------------------------ programa TypeScript

export function criarPrograma(raiz) {
  const tsconfig = path.join(raiz, "tsconfig.json");
  let opcoes = { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, baseUrl: raiz, paths: { "@/*": ["./*"] }, skipLibCheck: true, noEmit: true, types: [] };
  let arquivos;
  if (fs.existsSync(tsconfig)) {
    const lido = ts.readConfigFile(tsconfig, ts.sys.readFile);
    const conf = ts.parseJsonConfigFileContent(lido.config, ts.sys, raiz);
    opcoes = { ...conf.options, noEmit: true, skipLibCheck: true, types: [] };
    arquivos = conf.fileNames;
  } else {
    arquivos = ts.sys.readDirectory(raiz, [".ts", ".tsx"], ["node_modules"]);
  }
  const doApp = arquivos.filter((f) => {
    const n = f.replace(/\\/g, "/");
    return !n.includes("/node_modules/") && !n.includes("/__tests__/") && !n.endsWith(".d.ts") && !n.includes("/.expo/");
  });
  return { programa: ts.createProgram(doApp, opcoes), arquivos: doApp };
}

// ------------------------------------------------------------------ análise

export function analisar(raiz, politica) {
  const { programa, arquivos } = criarPrograma(raiz);
  const checker = programa.getTypeChecker();
  const doApp = new Set(arquivos.map((a) => path.resolve(a)));
  const fontesApp = programa.getSourceFiles().filter((sf) => doApp.has(path.resolve(sf.fileName)));
  const ehDoApp = (no) => no && doApp.has(path.resolve(no.getSourceFile().fileName));

  const NEUTROS = new Set(politica.campos_neutros ?? []);
  const HOOKS_SEM_DADO = new Set(["useCallback", "useEffect", "useLayoutEffect", "useFocusEffect", "useLocalSearchParams", "useSafeAreaInsets", "useColorScheme", "useContext", "setTimeout", "setInterval", "clearTimeout", "clearInterval", "require"]);
  const SEM_DADO = new Set(["includes", "has", "some", "every", "indexOf", "findIndex", "test", "startsWith", "endsWith", "localeCompare", "isNaN", "isFinite", "isInteger", "isArray", "keys"]);
  const NAO_PROPAGAM = new Set(politica.chamadas_que_nao_propagam ?? []);
  const CALLBACK_DO_RECEPTOR = new Set(["map", "forEach", "filter", "find", "flatMap", "some", "every", "sort", "then", "reduce", "findLast"]);
  const MUTAM_RECEPTOR = new Set(["push", "unshift", "add", "set", "concat", "splice", "append"]);

  const taintSimbolo = new Map(); // símbolo -> Map<rótulo, info>
  const taintCampos = new Map(); // símbolo -> Map<campo, Map<rótulo, info>>
  const setterParaEstado = new Map();
  const paramFantasma = new Map(); // símbolo de parâmetro -> rótulo fantasma
  const idFuncao = new Map(); // nó da função -> id estável
  const resumoRetorno = new Map(); // id -> Map<rótulo, info>
  const resumoSaidas = new Map(); // id -> Map<chave, {indice, campo, sum, no, trilha}>
  const fluxos = new Map();
  const fontesVistas = new Map();
  let mudou = true;

  const rel = (sf) => path.relative(raiz, sf.fileName).replace(/\\/g, "/");
  const local = (no) => {
    const sf = no.getSourceFile();
    return `${rel(sf)}:${sf.getLineAndCharacterOfPosition(no.getStart()).line + 1}`;
  };
  const vazio = () => new Map();
  const fantasma = (rot) => rot.startsWith(FANTASMA);

  // ---------------------------------------------------------------- taints

  function unir(a, b) {
    if (b.size === 0) return a;
    const r = new Map(a);
    for (const [rot, info] of b) {
      const atual = r.get(rot);
      if (!atual || (atual.sanitizado && !info.sanitizado)) r.set(rot, info);
    }
    return r;
  }
  const mudouMapa = (antes, depois) => depois.size !== antes.size || [...depois].some(([k, v]) => antes.get(k)?.sanitizado !== v.sanitizado);

  function passo(t, no, oque) {
    if (t.size === 0) return t;
    const onde = `${local(no)} ${oque}`;
    const r = new Map();
    for (const [rot, info] of t) r.set(rot, { ...info, trilha: info.trilha.at(-1) === onde ? info.trilha : [...info.trilha, onde].slice(-12) });
    return r;
  }
  /** Marca como limpo. Em parâmetro ainda não resolvido, guarda para quais rótulos vale (`para`). */
  function marcarSanitizado(t, rotulos) {
    const r = new Map();
    for (const [rot, info] of t) {
      if (fantasma(rot)) r.set(rot, { ...info, sanitizado: true, para: rotulos ?? null });
      else r.set(rot, !rotulos || rotulos.includes(rot) ? { ...info, sanitizado: true } : info);
    }
    return r;
  }
  /** Ao resolver o parâmetro, o rótulo real herda a limpeza feita lá dentro (se valer para ele). */
  const herdaLimpeza = (rotulo, real, dentro) => real.sanitizado || (dentro.sanitizado && (!dentro.para || dentro.para.includes(rotulo)));
  function adicionar(s, t, no, oque) {
    if (!s || t.size === 0) return;
    t = soDentroDaDona(s, t);
    if (t.size === 0) return;
    const antes = taintSimbolo.get(s) ?? vazio();
    const depois = unir(antes, passo(t, no, oque));
    if (mudouMapa(antes, depois)) {
      taintSimbolo.set(s, depois);
      mudou = true;
    }
  }
  function adicionarCampo(s, campo, t, no) {
    if (!s || t.size === 0) return;
    t = soDentroDaDona(s, t);
    if (t.size === 0) return;
    const campos = taintCampos.get(s) ?? new Map();
    const antes = campos.get(campo) ?? vazio();
    const depois = unir(antes, passo(t, no, `.${campo}`));
    if (mudouMapa(antes, depois)) {
      campos.set(campo, depois);
      taintCampos.set(s, campos);
      mudou = true;
    }
  }
  function todosOsCampos(s) {
    let t = vazio();
    for (const v of (taintCampos.get(s) ?? new Map()).values()) t = unir(t, v);
    return t;
  }

  // ---------------------------------------------------------------- símbolos e funções

  function simbolo(no) {
    if (!no) return undefined;
    // em { anotacao } o nome é ao mesmo tempo a propriedade e a variável: vale a variável
    let s = no.parent && ts.isShorthandPropertyAssignment(no.parent) && no.parent.name === no ? checker.getShorthandAssignmentValueSymbol(no.parent) : undefined;
    if (!s) s = checker.getSymbolAtLocation(no);
    if (s && s.flags & ts.SymbolFlags.Alias) {
      try {
        s = checker.getAliasedSymbol(s);
      } catch {
        /* alias quebrado */
      }
    }
    return s;
  }

  function declaracaoDeFuncao(s) {
    for (const d of s?.declarations ?? []) {
      if (ts.isFunctionDeclaration(d) || ts.isMethodDeclaration(d)) return d.body ? d : undefined;
      if ((ts.isVariableDeclaration(d) || ts.isPropertyAssignment(d)) && d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))) return d.initializer;
    }
    return undefined;
  }

  function nomeDaFuncao(fn) {
    if (fn.name && ts.isIdentifier(fn.name)) return fn.name.text;
    const p = fn.parent;
    if (p && (ts.isVariableDeclaration(p) || ts.isPropertyAssignment(p)) && ts.isIdentifier(p.name)) return p.name.text;
    return undefined;
  }

  const funcaoPorId = new Map();
  function idDe(fn) {
    if (!idFuncao.has(fn)) {
      const id = `${nomeDaFuncao(fn) ?? "anonima"}@${local(fn)}`;
      idFuncao.set(fn, id);
      funcaoPorId.set(id, fn);
    }
    return idFuncao.get(fn);
  }

  /** Parâmetro não resolvido só vale dentro da própria função: guardado em variável de fora, some. */
  function soDentroDaDona(s, t) {
    const decl = s?.valueDeclaration ?? s?.declarations?.[0];
    if (!decl) return t;
    let r = t;
    for (const rot of t.keys()) {
      if (!fantasma(rot)) continue;
      const dono = funcaoPorId.get(rot.slice(1, rot.lastIndexOf(":")));
      if (dono && !(decl.pos >= dono.pos && decl.end <= dono.end && decl.getSourceFile() === dono.getSourceFile())) {
        if (r === t) r = new Map(t);
        r.delete(rot);
      }
    }
    return r;
  }

  function funcaoEnvolvente(no) {
    let p = no.parent;
    while (p && !ts.isFunctionLike(p)) p = p.parent;
    return p;
  }

  /** Funções com resumo: as nomeadas do app (callbacks anônimos rodam no lugar). */
  function temResumo(fn) {
    return !!fn && ehDoApp(fn) && !!fn.body && (ts.isFunctionDeclaration(fn) || ts.isMethodDeclaration(fn) || ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && (ts.isVariableDeclaration(fn.parent) || ts.isPropertyAssignment(fn.parent))));
  }

  function semearParametros(fn) {
    if (!temResumo(fn)) return;
    const id = idDe(fn);
    fn.parameters.forEach((p, i) => {
      const semear = (nomeNo, rot) => {
        const s = simbolo(nomeNo);
        if (s && !paramFantasma.has(s)) {
          paramFantasma.set(s, rot);
          adicionar(s, new Map([[rot, { sanitizado: false, trilha: [] }]]), nomeNo, "parâmetro");
        }
      };
      if (ts.isIdentifier(p.name)) semear(p.name, `${FANTASMA}${id}:${i}`);
      else if (ts.isObjectBindingPattern(p.name)) {
        // parâmetro desestruturado ({ a, b }): cada nome é o campo correspondente
        for (const el of p.name.elements) {
          if (!ts.isIdentifier(el.name)) continue;
          const campo = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
          semear(el.name, `${FANTASMA}${id}:${i}${CAMPO}${campo}`);
        }
      }
    });
  }

  // ---------------------------------------------------------------- política

  function nomeEObjeto(chamada) {
    const e = chamada.expression;
    if (ts.isIdentifier(e)) return { nome: e.text };
    if (ts.isPropertyAccessExpression(e)) {
      const obj = e.expression;
      const objeto = ts.isIdentifier(obj) ? obj.text : ts.isPropertyAccessExpression(obj) ? obj.name.text : undefined;
      return { nome: e.name.text, objeto, receptor: obj };
    }
    return {};
  }
  const casa = (regra, nome, objeto, arquivo) =>
    (regra.chamada || regra.objeto) && (!regra.chamada || regra.chamada === nome) && (!regra.objeto || regra.objeto === objeto) && (!regra.arquivo || arquivo.includes(regra.arquivo));
  const fonteDe = (ch) => {
    const { nome, objeto } = nomeEObjeto(ch);
    return politica.fontes.find((f) => f.chamada && casa(f, nome, objeto, rel(ch.getSourceFile())));
  };
  const sanitizadorDe = (ch) => politica.sanitizadores.find((s) => s.chamada === nomeEObjeto(ch).nome);
  const sumidouroDe = (ch) => {
    const { nome, objeto } = nomeEObjeto(ch);
    return politica.sumidouros.find((s) => casa(s, nome, objeto, ""));
  };

  function registrarFonte(regra, no) {
    const chave = `${regra.rotulo}@${local(no)}`;
    if (!fontesVistas.has(chave)) fontesVistas.set(chave, { rotulo: regra.rotulo, onde: local(no), explicacao: regra.explicacao });
    return new Map([[regra.rotulo, { sanitizado: false, trilha: [`${local(no)} fonte: ${regra.explicacao}`] }]]);
  }

  // ---------------------------------------------------------------- expressões

  function semEmbrulho(e) {
    while (e && (ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e) || ts.isAsExpression(e) || ts.isAwaitExpression(e) || ts.isSatisfiesExpression?.(e))) e = e.expression;
    return e;
  }

  function taintDe(e, prof = 0) {
    if (!e || prof > 60) return vazio();
    switch (e.kind) {
      case ts.SyntaxKind.Identifier: {
        const s = simbolo(e);
        return s ? unir(taintSimbolo.get(s) ?? vazio(), todosOsCampos(s)) : vazio();
      }
      case ts.SyntaxKind.ParenthesizedExpression:
      case ts.SyntaxKind.AwaitExpression:
      case ts.SyntaxKind.AsExpression:
      case ts.SyntaxKind.NonNullExpression:
      case ts.SyntaxKind.TypeAssertionExpression:
      case ts.SyntaxKind.SatisfiesExpression:
      case ts.SyntaxKind.SpreadElement:
      case ts.SyntaxKind.SpreadAssignment:
      case ts.SyntaxKind.JsxExpression:
        return taintDe(e.expression, prof + 1);
      case ts.SyntaxKind.PropertyAccessExpression:
        return taintDoCampo(e.expression, e.name.text, prof + 1);
      case ts.SyntaxKind.ElementAccessExpression:
        return taintDe(e.expression, prof + 1);
      case ts.SyntaxKind.TemplateExpression:
        return e.templateSpans.reduce((acc, sp) => unir(acc, taintDe(sp.expression, prof + 1)), vazio());
      case ts.SyntaxKind.ConditionalExpression:
        return unir(taintDe(e.whenTrue, prof + 1), taintDe(e.whenFalse, prof + 1));
      case ts.SyntaxKind.BinaryExpression: {
        const op = e.operatorToken.kind;
        const juntam = [ts.SyntaxKind.PlusToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.CommaToken, ts.SyntaxKind.EqualsToken, ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.SlashToken];
        return juntam.includes(op) ? unir(taintDe(e.left, prof + 1), taintDe(e.right, prof + 1)) : vazio();
      }
      case ts.SyntaxKind.ObjectLiteralExpression: {
        let t = vazio();
        for (const p of e.properties) {
          if (ts.isPropertyAssignment(p)) t = unir(t, taintDe(p.initializer, prof + 1));
          else if (ts.isShorthandPropertyAssignment(p)) {
            const s = checker.getShorthandAssignmentValueSymbol(p);
            if (s) t = unir(t, unir(taintSimbolo.get(s) ?? vazio(), todosOsCampos(s)));
          } else if (ts.isSpreadAssignment(p)) t = unir(t, taintDe(p.expression, prof + 1));
        }
        return t;
      }
      case ts.SyntaxKind.ArrayLiteralExpression:
        return e.elements.reduce((acc, x) => unir(acc, taintDe(x, prof + 1)), vazio());
      case ts.SyntaxKind.NewExpression:
        return (e.arguments ?? []).reduce((acc, x) => unir(acc, taintDe(x, prof + 1)), vazio());
      case ts.SyntaxKind.CallExpression:
        return taintDeChamada(e, prof + 1);
      default:
        return vazio();
    }
  }

  /** objeto.campo: com campos conhecidos, só aquele campo; parâmetro vira fantasma com campo. */
  function taintDoCampo(objExpr, campo, prof) {
    if (NEUTROS.has(campo)) return vazio();
    const base = semEmbrulho(objExpr);
    if (base && ts.isIdentifier(base)) {
      const s = simbolo(base);
      if (s) {
        let objeto = taintSimbolo.get(s) ?? vazio();
        const pf = paramFantasma.get(s);
        if (pf && !pf.includes(CAMPO)) {
          // parâmetro inteiro (§f:0) vira o campo pedido (§f:0~campo)
          const sem = new Map(objeto);
          sem.delete(pf);
          objeto = unir(sem, new Map([[`${pf}${CAMPO}${campo}`, { sanitizado: false, trilha: [] }]]));
        }
        const campos = taintCampos.get(s);
        return campos ? unir(objeto, campos.get(campo) ?? vazio()) : objeto;
      }
    }
    if (base && ts.isObjectLiteralExpression(base)) {
      const p = base.properties.find((x) => x.name && ts.isIdentifier(x.name) && x.name.text === campo);
      if (p && ts.isPropertyAssignment(p)) return taintDe(p.initializer, prof + 1);
      if (p && ts.isShorthandPropertyAssignment(p)) return taintDe(p.name, prof + 1);
      if (!base.properties.some((x) => ts.isSpreadAssignment(x))) return vazio();
    }
    return taintDe(objExpr, prof + 1);
  }

  const argumentos = (ch, prof) => ch.arguments.reduce((acc, a) => unir(acc, taintDe(a, prof + 1)), vazio());

  /** Taint do argumento `arg` para o fantasma (índice e campo opcional). */
  function taintDoArgumento(arg, campo, prof) {
    return campo ? taintDoCampo(arg, campo, prof + 1) : taintDe(arg, prof + 1);
  }

  /** Troca os fantasmas do resumo da função chamada pelo taint dos argumentos desta chamada. */
  function resolver(t, idChamada, args, chamada, prof) {
    let r = vazio();
    const prefixo = `${FANTASMA}${idChamada}:`;
    for (const [rot, info] of t) {
      if (!rot.startsWith(prefixo)) {
        r = unir(r, new Map([[rot, info]]));
        continue;
      }
      const [indice, campo] = rot.slice(prefixo.length).split(CAMPO);
      const arg = args[Number(indice)];
      if (!arg) continue;
      const ta = passo(taintDoArgumento(arg, campo, prof), chamada, `entra em ${idChamada.split("@")[0]}()`);
      const comTrilha = new Map();
      for (const [k, v] of ta) {
        const limpo = herdaLimpeza(k, v, info);
        comTrilha.set(k, fantasma(k) && info.sanitizado ? { ...v, sanitizado: true, para: info.para, trilha: [...v.trilha, ...info.trilha].slice(-14) } : { sanitizado: limpo, trilha: [...v.trilha, ...info.trilha].slice(-14) });
      }
      r = unir(r, comTrilha);
    }
    return r;
  }

  function taintDeChamada(chamada, prof) {
    const fonte = fonteDe(chamada);
    if (fonte) return registrarFonte(fonte, chamada);
    const { nome, receptor } = nomeEObjeto(chamada);

    if (nome && HOOKS_SEM_DADO.has(nome)) return vazio();
    if (nome === "useMemo") {
      const cb = chamada.arguments[0];
      return cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) ? retornoLocal(cb, prof) : vazio();
    }
    if (nome === "useState" || nome === "useRef") return chamada.arguments[0] ? taintDe(chamada.arguments[0], prof + 1) : vazio();

    const san = sanitizadorDe(chamada);
    const entrada = () => unir(argumentos(chamada, prof), receptor ? taintDe(receptor, prof + 1) : vazio());
    if (san) return san.condicional || san.rotulos ? passo(marcarSanitizado(entrada(), san.rotulos), chamada, `limpo por ${nome}()`) : vazio();

    const fn = declaracaoDeFuncao(simbolo(chamada.expression));
    if (temResumo(fn)) {
      const id = idDe(fn);
      return resolver(resumoRetorno.get(id) ?? vazio(), id, chamada.arguments, chamada, prof);
    }
    if (nome && (SEM_DADO.has(nome) || NAO_PROPAGAM.has(nome))) return vazio();
    const sum = sumidouroDe(chamada);
    if (sum && sum.tipo === "rede") return vazio(); // o que volta da rede é do servidor
    // função de fora (JSON.stringify, String, encodeURIComponent...): o dado passa por ela
    return passo(entrada(), chamada, `${nome ?? "chamada"}()`);
  }

  /** Retorno de uma função anônima avaliada no lugar (callback de useMemo). */
  function retornoLocal(fn, prof) {
    if (!ts.isBlock(fn.body)) return taintDe(fn.body, prof + 1);
    let t = vazio();
    const visitarRet = (n) => {
      if (ts.isReturnStatement(n) && n.expression && funcaoEnvolvente(n) === fn) t = unir(t, taintDe(n.expression, prof + 1));
      if (!ts.isFunctionLike(n)) ts.forEachChild(n, visitarRet);
    };
    ts.forEachChild(fn.body, visitarRet);
    return t;
  }

  // ---------------------------------------------------------------- ligar valores a nomes

  const campoDoElemento = (el) => (el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : undefined);

  function ligar(nome, t, no, oque) {
    if (!nome || t.size === 0) return;
    if (ts.isIdentifier(nome)) adicionar(simbolo(nome), t, no, oque);
    else if (ts.isObjectBindingPattern(nome)) {
      for (const el of nome.elements) if (!NEUTROS.has(campoDoElemento(el))) ligar(el.name, t, no, oque);
    } else if (ts.isArrayBindingPattern(nome)) {
      for (const el of nome.elements) if (!ts.isOmittedExpression(el)) ligar(el.name, t, no, oque);
    }
  }

  function ligarValor(nome, valor, no, oque) {
    if (!nome || !valor) return;
    const v = semEmbrulho(valor);
    if (ts.isIdentifier(nome)) {
      const destino = simbolo(nome);
      if (ts.isObjectLiteralExpression(v) && !v.properties.some((p) => ts.isSpreadAssignment(p))) {
        for (const p of v.properties) {
          if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) adicionarCampo(destino, p.name.text, taintDe(p.initializer), no);
          else if (ts.isShorthandPropertyAssignment(p)) adicionarCampo(destino, p.name.text, taintDe(p.name), no);
        }
        return;
      }
      if (ts.isIdentifier(v)) {
        const origem = simbolo(v);
        const campos = origem && taintCampos.get(origem);
        if (campos) {
          for (const [c, tc] of campos) adicionarCampo(destino, c, tc, no);
          adicionar(destino, taintSimbolo.get(origem) ?? vazio(), no, oque);
          return;
        }
      }
    }
    if (ts.isObjectBindingPattern(nome)) {
      // const { a, b } = objeto: cada nome pega o seu campo
      for (const el of nome.elements) {
        const campo = campoDoElemento(el);
        if (!campo || NEUTROS.has(campo)) continue;
        ligar(el.name, taintDoCampo(v, campo, 0), no, oque);
      }
      return;
    }
    ligar(nome, taintDe(valor), no, oque);
  }

  const alvoDeAtribuicao = (esq) => {
    let e = esq;
    while (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) e = e.expression;
    return ts.isIdentifier(e) ? e : undefined;
  };

  function adicionarRetorno(fn, t, no) {
    if (!temResumo(fn) || t.size === 0) return;
    const id = idDe(fn);
    const antes = resumoRetorno.get(id) ?? vazio();
    const depois = unir(antes, passo(t, no, "retorna"));
    if (mudouMapa(antes, depois)) {
      resumoRetorno.set(id, depois);
      mudou = true;
    }
  }

  // ---------------------------------------------------------------- saídas

  function chegouNaSaida(t, sum, chamada) {
    for (const [rot, info] of t) {
      if (fantasma(rot)) {
        // ainda é parâmetro: entra no resumo da função dona do parâmetro
        const sep = rot.lastIndexOf(":");
        const idDono = rot.slice(1, sep);
        const [indice, campo] = rot.slice(sep + 1).split(CAMPO);
        const saidas = resumoSaidas.get(idDono) ?? new Map();
        const chave = `${indice}.${campo ?? ""}|${sum.tipo}|${local(chamada)}|${info.sanitizado ? "limpo" : "cru"}`;
        if (!saidas.has(chave)) {
          saidas.set(chave, { indice: Number(indice), campo, sum, no: chamada, sanitizado: info.sanitizado, para: info.para ?? null, trilha: info.trilha });
          resumoSaidas.set(idDono, saidas);
          mudou = true;
        }
      } else registrarFluxo(rot, info, sum, chamada);
    }
  }

  function registrarFluxo(rotulo, info, sum, chamada) {
    const perm = politica.permitidos.find((p) => p.rotulo === rotulo && p.tipo === sum.tipo);
    let veredito = "violacao";
    let porque = `Dado de ${rotulo} chega a ${sum.tipo}: ${sum.explicacao}.`;
    if (perm && (!perm.so_sanitizado || info.sanitizado)) {
      veredito = "permitido";
      porque = perm.explicacao;
    } else if (perm?.so_sanitizado) porque = `Só é permitido depois de limpar o dado (${perm.explicacao}), e aqui ele chega cru.`;
    const onde = local(chamada);
    const chave = `${rotulo}|${sum.tipo}|${onde}|${info.trilha[0] ?? ""}`;
    const anterior = fluxos.get(chave);
    if (anterior && !(anterior.veredito === "permitido" && veredito === "violacao")) return;
    fluxos.set(chave, {
      rotulo,
      sumidouro: sum.tipo,
      chamada: chamada.expression.getText().slice(0, 60),
      onde,
      fonte: info.trilha[0] ?? "",
      veredito,
      sanitizado: info.sanitizado,
      porque,
      trilha: [...info.trilha, `${onde} sai por ${chamada.expression.getText().slice(0, 40)}()`],
    });
  }

  // ---------------------------------------------------------------- visita

  function visitar(no) {
    if (ts.isFunctionLike(no) && no.parameters) {
      semearParametros(no);
      const nome = nomeDaFuncao(no);
      for (const f of politica.fontes.filter((x) => x.parametro && x.parametro === nome)) {
        const p = no.parameters[f.indice ?? 0];
        if (p) ligar(p.name, registrarFonte(f, p), p, "parâmetro");
      }
    }

    if (ts.isVariableDeclaration(no) && no.initializer) {
      if (ts.isArrayBindingPattern(no.name) && ts.isCallExpression(no.initializer) && nomeEObjeto(no.initializer).nome === "useState") {
        const [estado, setter] = no.name.elements;
        if (estado && setter && !ts.isOmittedExpression(estado) && !ts.isOmittedExpression(setter)) {
          setterParaEstado.set(simbolo(setter.name), simbolo(estado.name));
          const arq = rel(no.getSourceFile());
          for (const f of politica.fontes.filter((x) => x.estado_em && arq.includes(x.estado_em))) ligar(estado.name, registrarFonte(f, no), no, "estado do formulário");
          ligar(estado.name, taintDe(no.initializer.arguments[0]), no, "valor inicial");
        }
      } else ligarValor(no.name, no.initializer, no, `= ${no.name.getText().slice(0, 30)}`);
    }

    if (ts.isBinaryExpression(no) && no.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && no.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
      const alvo = alvoDeAtribuicao(no.left);
      if (alvo) {
        if (ts.isPropertyAccessExpression(no.left) && no.left.expression === alvo) adicionarCampo(simbolo(alvo), no.left.name.text, taintDe(no.right), no);
        else adicionar(simbolo(alvo), taintDe(no.right), no, `${alvo.text} =`);
      }
    }

    if (ts.isForOfStatement(no) && ts.isVariableDeclarationList(no.initializer)) {
      for (const d of no.initializer.declarations) ligar(d.name, taintDe(no.expression), no, "for...of");
    }

    if (ts.isReturnStatement(no) && no.expression) adicionarRetorno(funcaoEnvolvente(no), taintDe(no.expression), no);
    if (ts.isArrowFunction(no) && !ts.isBlock(no.body)) adicionarRetorno(no, taintDe(no.body), no.body);

    if (ts.isCallExpression(no)) visitarChamada(no);

    ts.forEachChild(no, visitar);
  }

  function visitarChamada(chamada) {
    const { nome, receptor } = nomeEObjeto(chamada);
    const args = chamada.arguments;
    const sAlvo = simbolo(chamada.expression);

    const estado = sAlvo && setterParaEstado.get(sAlvo);
    if (estado && args[0] && !ts.isArrowFunction(args[0])) adicionar(estado, taintDe(args[0]), chamada, "setState");

    // função do app com resumo: o que entra pelos parâmetros e chega a uma saída, sai daqui
    const fn = declaracaoDeFuncao(sAlvo);
    if (temResumo(fn)) {
      for (const s of (resumoSaidas.get(idDe(fn)) ?? new Map()).values()) {
        const arg = args[s.indice];
        if (!arg) continue;
        const ta = passo(taintDoArgumento(arg, s.campo, 0), chamada, `entra em ${nome ?? "função"}()`);
        const comTrilha = new Map();
        for (const [k, v] of ta) {
          const trilha = [...v.trilha, ...s.trilha].slice(-14);
          comTrilha.set(k, fantasma(k) && s.sanitizado ? { ...v, sanitizado: true, para: s.para, trilha } : { sanitizado: herdaLimpeza(k, v, s), trilha });
        }
        chegouNaSaida(comTrilha, s.sum, s.no);
      }
    }

    if (receptor && nome && CALLBACK_DO_RECEPTOR.has(nome)) {
      const cb = args[0];
      if (cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb))) {
        const i = nome === "reduce" ? 1 : 0;
        if (cb.parameters[i]) ligar(cb.parameters[i].name, taintDe(receptor), cb, `.${nome}()`);
      }
    }

    if (receptor && nome && MUTAM_RECEPTOR.has(nome)) {
      const alvo = alvoDeAtribuicao(receptor);
      if (alvo) adicionar(simbolo(alvo), argumentos(chamada, 0), chamada, `.${nome}()`);
    }

    const sum = sumidouroDe(chamada);
    if (sum) chegouNaSaida(argumentos(chamada, 0), sum, chamada);
  }

  // ---------------------------------------------------------------- ponto fixo

  let rodadas = 0;
  while (mudou && rodadas < 40) {
    mudou = false;
    rodadas++;
    for (const sf of fontesApp) visitar(sf);
  }

  if (process.env.TAINT_DEBUG) {
    for (const [id, ret] of resumoRetorno) if (id.startsWith(process.env.TAINT_DEBUG)) console.error("RETORNO", id, JSON.stringify([...ret].map(([k, v]) => [k, v.sanitizado, v.para])));
  }
  const lista = [...fluxos.values()].sort((a, b) => (a.veredito === b.veredito ? a.onde.localeCompare(b.onde) : a.veredito === "violacao" ? -1 : 1));
  const contagem = {};
  for (const f of lista) contagem[`${f.rotulo} -> ${f.sumidouro} (${f.veredito})`] = (contagem[`${f.rotulo} -> ${f.sumidouro} (${f.veredito})`] ?? 0) + 1;
  return {
    app: path.basename(path.resolve(raiz)),
    arquivos_analisados: fontesApp.length,
    funcoes_com_resumo: idFuncao.size,
    rodadas_ate_ponto_fixo: rodadas,
    fontes: [...fontesVistas.values()],
    fluxos: lista,
    resumo: {
      violacoes: lista.filter((f) => f.veredito === "violacao").length,
      permitidos: lista.filter((f) => f.veredito === "permitido").length,
      por_tipo: contagem,
    },
  };
}

// ------------------------------------------------------------------ linha de comando

function lerArgs(argv) {
  const args = { app: null, politica: path.join(aqui, "politica.json"), saida: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--politica") args.politica = argv[++i];
    else if (argv[i] === "--saida") args.saida = argv[++i];
    else args.app = argv[i];
  }
  if (!args.app) throw new Error("informe a pasta do app: node taint_ts/analisar.mjs ../GS-MOBILE-AQUENDA");
  return args;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = lerArgs(process.argv.slice(2));
  const politica = JSON.parse(fs.readFileSync(args.politica, "utf8"));
  const relatorio = analisar(path.resolve(args.app), politica);
  const json = JSON.stringify(relatorio, null, 2);
  if (args.saida) fs.writeFileSync(args.saida, json);
  else process.stdout.write(json + "\n");
  process.exitCode = relatorio.resumo.violacoes > 0 ? 2 : 0;
}
