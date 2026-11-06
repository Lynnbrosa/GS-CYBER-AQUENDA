// Fontes: o que vem do SQLite do celular.
export async function listarLembretes() {
  return [{ id: 1, titulo: "estradiol", anotacao: "2 mg", hora: 20, minuto: 0 }];
}
export async function obterConsulta(id: number) {
  return { id, titulo: "endocrinologista", local: "CR POP TT", dataHora: "2026-11-20T14:00:00Z" };
}
